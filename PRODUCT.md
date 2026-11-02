# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Sistem yöneticileri ve geliştiriciler: kendi Linux sunucusunu (VDS) tek başına işleten, bir ekip güvenlik aracı olmadan sunucusunu korumak isteyen kişiler. Panele tarayıcıdan, çoğunlukla masaüstünde, bazen telefondan bakarlar; bir şey ters gittiğinde (saldırı şüphesi) hızlıca durumu okumak ve ne yapacaklarını öğrenmek isterler. İlk kullanıcı ve ürün sahibi: Ömer (kendi VDS'i). Açık kaynak ya da satış olarak başkalarına da sunulacak.

## Product Purpose
NexGuard, tek bir sunucunun güvenlik durumunu gösteren yerel bir panel: OPSEC denetimi, DDoS izleme ve eşik bildirimi, kaynak IP'lerin ülke/ASN/Tor-VPN işaretleriyle canlı haritası. Başarı: kullanıcı panele bakınca sunucunun güvenli mi saldırı altında mı olduğunu saniyeler içinde anlar ve hangi önlemi uygulayacağını bilir.

## Positioning
Gizlilik odaklı ve yerel çalışır: hiçbir veri dışarı çıkmaz, IP sorguları yerel veritabanında yapılır, panel root gerektirmez, düzeltmeleri yalnızca önerir ve otomatik uygulamaz. Bunun üstüne canlı saldırı görünürlüğü gelir (bağlantı kaynaklarının dünya haritasında gösterimi). Bulut tabanlı güvenlik panellerinin kopyalayamayacağı şey: verinin makineden hiç çıkmaması.

## Operating Context
Panel `127.0.0.1` üzerinde çalışır, uzak erişim SSH tüneliyle yapılır. Giriş: kullanıcı adı + parola, isteğe bağlı 2FA (TOTP), CSRF korumalı. Linux (`/proc`, systemd, nftables) ortamı. Bildirim kanalları: Telegram ve webhook.

## Capabilities and Constraints
- Modüller: Genel Bakış, Denetim (audit), DDoS izleme, Canlı harita, Coğrafya (DB-IP Lite + Tor çıkış listesi), Ayarlar.
- Harita ve veri tamamen yerel; harita verisi Natural Earth (kamu malı), coğrafya verisi DB-IP Lite (CC BY 4.0, atıf gerekir).
- Harita yalnızca TCP bağlantı kaynaklarını gösterir; hat doyuran UDP/ICMP saldırılarının kaynağı görünmez ve arayüz bunu dürüstçe söylemelidir.
- Volumetrik saldırılar sunucuda durdurulamaz; ürün tespit, bildirim ve sertleştirme önerisi sunar.
- Teknoloji: FastAPI, Jinja2 şablonları, tek CSS dosyası, kısıtlı CSP (yalnızca kendi kaynağından script ve stil).

## Brand Commitments
Ad: NexGuard. Arayüz dili Türkçe. Kullanıcı arayüzünde emoji yok; ikonlar SVG. Kullanıcı, mevcut arayüzü "çok AI slop" buldu: jenerik, gradyanlı, süslü görünüm istenmiyor. Bağlayıcı görsel referans (Ömer, 2026-11-02): Musemind "VEXORA" panosu (dribbble.com/shots/26980609): kömür zemin, yuvarlak paneller, hap menü, sağda dev harita ve süzülen panel, renkli metrik karoları, sayarak yerine oturan sayılar.

## Evidence on Hand
Çalışan bir kod tabanı ve 37 otomatik test (`tests/`). Gerçek müşteri, referans, kıyaslama ya da fiyat verisi yok; bunlar uydurulmamalıdır.

## Product Principles
1. Okunabilirlik süsten önce gelir: durum, bir saniyede, önce okunur.
2. Dürüstlük: ürün neyi göremediğini ve neyi yapamadığını açıkça söyler.
3. Veri makineden çıkmaz; gizlilik bir özelliktir ve arayüzde de hissedilir.
4. Panel öneri sunar, kullanıcı onaylamadan hiçbir şeyi değiştirmez.
5. Yoğun ama sakin: durum (normal, uyarı, saldırı) renkle ve metinle her zaman ayırt edilir; karo renkleri kimlik taşır, durum bildirmez. Grafikler ve sayılar yalnız gerçek veriden gelir.

## Accessibility & Inclusion
Mobil ve masaüstünde kullanılabilir olmalı. Renk tek başına anlam taşımamalı (durum metinle de belirtilir). Hareket azaltma tercihine saygı duyulur.
