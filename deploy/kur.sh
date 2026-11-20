#!/bin/sh
# NexGuard ek bileşenleri: paket algılayıcı, engel yardımcısı ve TCP tuzağı. root olarak çalıştırın.
# Panelin kendisi /opt/nexguard altında ve nexguard.service olarak kurulu olmalı.
set -eu
cd "$(dirname "$0")"
install -m 0755 -o root -g root nexguard-engel /usr/local/sbin/nexguard-engel
install -d -m 0755 /etc/nexguard
[ -f /etc/nexguard/izinli ] || printf '# Asla engellenmeyecek IP/ağlar, satır başına bir tane (ör. 203.0.113.7 veya 198.51.100.0/24)\n' > /etc/nexguard/izinli
for u in nexguard-sensor.service nexguard-engel.service nexguard-engel.path nexguard-engel.timer nexguard-tcptuzak.service; do
  install -m 0644 "$u" /etc/systemd/system/"$u"
done
systemctl daemon-reload
# TCP tuzağı panelden açılana kadar hiçbir port dinlemez.
systemctl enable --now nexguard-sensor.service nexguard-engel.path nexguard-engel.timer nexguard-tcptuzak.service
echo "Kuruldu. Algılayıcı: systemctl status nexguard-sensor  |  Engel: nft list table inet nexguard  |  TCP tuzağı: systemctl status nexguard-tcptuzak"
echo "Not: tuzak portlarının dışarıdan ulaşılabilmesi için güvenlik duvarında açılması gerekir (ör. ufw allow 2323/tcp)."
