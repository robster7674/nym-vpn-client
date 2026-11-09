# usage: sh e2e2.sh <log-name> [nym-vpnc connect args...]
# Runs a full connect/verify/disconnect cycle. A detached watchdog restores networking after 240s.
LOG=~/$1.log; shift
GW=10.164.0.1
exec > "$LOG" 2>&1
restore() {
  sudo service nym_vpnd stop
  sudo pfctl -a nym -F all; sudo pfctl -F all; sudo pfctl -d
  sudo route -n delete default >/dev/null 2>&1; sudo route -n add default $GW
  sudo cp /tmp/resolv.before /etc/resolv.conf
}
echo "== start $(date)"
echo "external ip before: $(curl -s --max-time 10 https://ipinfo.io/ip)"
cp /etc/resolv.conf /tmp/resolv.before
netstat -rn -f inet > /tmp/routes.before
( sleep 240; echo "== watchdog fired $(date)"; restore ) </dev/null >/dev/null 2>&1 &
WD=$!
nym-vpnc connect "$@"
for i in $(seq 1 60); do
  st=$(nym-vpnc status 2>&1 | head -3 | tr '\n' ' ')
  echo "$(date +%T) $st"
  case "$st" in *Connected*|*Error*) break;; esac
  sleep 3
done
sleep 5
echo "== status"; nym-vpnc status
echo "== ifconfig tun"; ifconfig | grep -A6 "^tun"
echo "== routes"; netstat -rn -f inet; netstat -rn -f inet6 | head -12
echo "== resolv.conf"; cat /etc/resolv.conf
echo "== pf"; sudo pfctl -s info | head -1; sudo pfctl -s rules; sudo pfctl -a nym -s rules
echo "== ip literal: $(curl -s --max-time 15 http://1.1.1.1 -o /dev/null -w "%{http_code}")  ping: $(ping -c2 -t6 1.1.1.1 2>&1 | tail -2 | tr "\n" " ")"
echo "== external ip via tunnel: $(curl -s --max-time 25 https://ipinfo.io/ip)"
echo "== dns: $(host -W 10 example.com 2>&1 | head -2)"
echo "== bypass attempt (must fail): $(curl -s --max-time 8 --interface vtnet0 https://ipinfo.io/ip; echo rc=$?)"
echo "== disconnect"; nym-vpnc disconnect; sleep 8
nym-vpnc status
echo "== after"; diff /etc/resolv.conf /tmp/resolv.before && echo "resolv.conf restored"
netstat -rn -f inet | diff - /tmp/routes.before && echo "routes restored"
sudo pfctl -s info | head -1; sudo pfctl -a nym -s rules | wc -l
echo "external ip after: $(curl -s --max-time 10 https://ipinfo.io/ip)"
echo "== daemon log"; sudo tail -60 /var/log/messages | grep -i nym
# only stand the watchdog down once disconnect really finished
nym-vpnc status | grep -q Disconnected && netstat -rn -f inet | grep -q "^default.*vtnet0" && kill $WD 2>/dev/null
echo "== done $(date)"
