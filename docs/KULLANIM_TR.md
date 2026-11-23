# DarkWatch AI 0.2.0 – Kısa Kullanım Kılavuzu

DarkWatch AI (eski adıyla DarkWeb Monitor), yapay zekâ destekli, açık kaynak bir darknet izleme ve tehdit istihbaratı platformudur.

## Kurulum
1. `.env.example` dosyasını `.env` olarak kopyalayın.
2. Tor'u başlatın (daemon: port 9050, Tor Browser: 9150 → `TOR_PROXY_PORT=9150`).
3. İsteğe bağlı: Ollama kurup `ollama pull qwen2.5:7b` çalıştırın (yerel AI).
4. `pip install -r requirements.txt` → `python -m darkweb_monitor.cli init` → `python -m darkweb_monitor.cli serve`
5. Tarayıcıda `http://127.0.0.1:8000` adresini açın.

## İlk adımlar
- **Organizations (Kurumlar)**: Önce şirketinizi kurum olarak ekleyin. Alan adlarını, markaları, çalışan e-postalarını ve yönetici adlarını kurumun varlıkları olarak girin (çok sayıda e-postayı toplu yapıştırabilirsiniz). Bu varlıklar otomatik olarak izleme terimine dönüşür; alarmlar, risk skoru ve maruziyet kurum bazında izlenir.
- **Watchlist**: Hiçbir kuruma ait olmayan genel terimler için hâlâ kullanılabilir. Crawler, HIBP, IntelX ve ransomware kontrolleri bu listeyi kullanır.
- **Targets**: İzleme yetkiniz olan .onion adreslerini ekleyin. Her hedef için tarama modunu seçin:
  - *Standard*: klasik, sıralı tarama
  - *Smart*: AI, linkleri watchlist'e göre önceliklendirir
  - *Agent*: AI, verdiğiniz hedefe göre adım adım hangi sayfaya gideceğine karar verir ve hedefe ulaşınca durur
- **Zamanlama**: Her hedefe "6 saatte bir", "günlük" veya cron ifadesi verebilirsiniz.
- **AI Tasks**: Her taramadan sonra AI veya kurallar yeni görevler önerir (yeniden tarama, yeni hedef, yeni watch terimi, analist incelemesi). Yeni hedefler **her zaman** sizin onayınızı bekler.
- **Intel sources**: HIBP, IntelX ve ransomware sızıntı siteleri, API anahtarları `.env` dosyasına girildiğinde otomatik çalışır.

## Tehdit istihbaratı (DarkWatch)
- **Tehdit sınıflandırması**: Her alarm 12 sınıftan birine atanır (ransomware, ilk erişim satışı, kimlik bilgisi sızıntısı, veri ihlali, içeriden kişi arayışı, exploit, zararlı yazılım, oltalama, dolandırıcılık, doxxing, DDoS, anılma). Yerel AI'ın sayfa kategorisi, anahtar kelimeler, kaynak ve IOC türleri birlikte değerlendirilir; güven oranı, sinyaller ve MITRE ATT&CK ipucu gösterilir.
- **Risk skoru (0–100)**: Her alarm için gerekçeleriyle birlikte hesaplanır (önem derecesi, tehdit sınıfı, eşleşen varlık türü, AI triyaj kararı, tekrar sayısı, bilinen tehdit aktörü). Kurum skoru en kötü açık alarmdan başlar, diğer alarmlar azalan katkıyla eklenir; alarmların ağırlığı `RISK_HALF_LIFE_DAYS` günde bir yarıya iner.
- **Forum izleme ve tehdit aktörleri**: Crawler forum sayfalarındaki gönderileri (phpBB, XenForo, MyBB, vBulletin, SMF, Discourse ve genel yapı) ayrıştırır. Varlıklarınızdan söz eden gönderilerin yazarları tehdit aktörü olarak kaydedilir; gönderideki Telegram, Jabber, Tox ve Session iletişim bilgileri aktöre bağlanır. Ransomware grupları da aktör olarak profillenir. Aynı iletişim bilgisini kullanan aktörler etiketlenir; gerektiğinde aktörleri birleştirebilirsiniz.
- **Varlık ilişki grafiği**: **Entity graph** sayfası kurumları, varlıkları, alarmları, siteleri, IOC'leri ve aktörleri birbirine bağlı gösterir. Bir düğüme tıklayınca grafik o düğüm etrafında yeniden çizilir, çift tıklayınca ayrıntısı açılır.
- **Değişiklik tespiti**: Bir .onion sayfası değiştiğinde eklenen ve silinen satırlar saklanır; eklenen metinde izlenen bir terim varsa ayrıca belirtilir.

## Delil saklama
- Önem derecesi `EVIDENCE_AUTO_SEVERITY` (varsayılan: high) ve üzeri olan alarmların delili otomatik alınır; alarm penceresindeki **Capture evidence** düğmesiyle elle de alınabilir.
- Delil, gözlemlenen sayfanın (parolalar maskelenmiş) kanonik JSON kaydıdır. SHA-256 özetiyle adreslenir ve sıkıştırılarak `data/evidence/` altında saklanır.
- Alma, doğrulama, indirme, dışa aktarma, yasal saklama (legal hold) ve IncidentForge'a aktarma işlemleri **zincirleme hash'li bir delil zinciri (chain of custody)** kaydına yazılır. **Verify integrity** düğmesi dosyayı ve zinciri yeniden doğrular; dosyada ya da kayıtta yapılan herhangi bir değişiklik raporlanır.
- **Alert bundle (.zip)**: manifest, tüm delil kayıtları ve `SHA256SUMS` dosyasını içerir. Sayfa saklama süresi (retention) delilleri silmez.

## Çok kiracılı kullanım (multi-tenant)
- Toplama altyapısı ortaktır; her kurum yalnızca kendi varlıklarının eşleştiği alarmları görür.
- Kurum penceresindeki **+ Tenant API key** düğmesi `dwk_…` biçiminde bir anahtar üretir. Anahtar yalnızca bir kez gösterilir ve hash'lenerek saklanır. Bu anahtar sadece `/api/orgs/{kurum}/…` uçlarını açar (varlıklar, alarmlar, risk, maruziyet, deliller); genel API'ye erişemez.

- Kiracılar yalnızca henüz izlenmeyen değerleri ekleyebilir; zaten izlenen bir alan adını kuruma yalnızca yönetici atayabilir. Böylece bir kiracı başka bir şirketin alan adını sahiplenip onun alarmlarını göremez. Kiracılar `regex` ve `keyword` varlığı ekleyemez ve ortak alarmlarda yalnızca kendi eşleşmelerini görür.

## IncidentForge entegrasyonu
- `.env` içinde `INCIDENTFORGE_URL` ve `INCIDENTFORGE_API_KEY` tanımlayın. Alarm penceresindeki **→ IncidentForge** düğmesi alarmı; tehdit sınıfı, risk skoru, ilgili kurumlar, tehdit aktörleri, IOC'ler ve delil zinciriyle birlikte tek bir olay kaydı (`darkwatch.incident/1`) olarak gönderir.
- `INCIDENTFORGE_AUTO_SEVERITY=critical` ile kritik alarmlar otomatik olarak olaya dönüştürülür. Böylece sızdırılmış veriden başlayıp olay müdahalesi ve adli incelemeye uzanan bütünleşik bir süreç elde edilir.

## Gizlilik
- Ham dark web içeriği varsayılan olarak **sadece yerel modele** gider (`CLOUD_ALLOW_RAW=false`).
- Bulut modeline yalnızca özetler gider; e-posta, IP, cüzdan ve parolalar maskelenir.
- E-posta:parola sızıntılarında parola **hiçbir zaman** saklanmaz.
- `RETENTION_DAYS` süresi dolan sayfa içerikleri otomatik silinir (GDPR / KVKK).

## Güvenlik
- `TOR_REQUIRED=true` iken Tor doğrulanmadan tarama başlamaz (gerçek IP'nizi korur).
- Sunucuyu ağa açacaksanız `API_KEY` tanımlamak zorunludur.
- Crawler pasiftir: giriş yapmaz, form göndermez, dosya indirmez.

## AI Analist
- Bir alarmı açıp **"Investigate with AI"** düğmesine basın ya da **AI Analyst** sayfasından serbest bir soru sorun.
- Analist; alarmı, sayfayı (parça parça ya da "sayfa okuyucu" alt-agent ile), benzer alarmları ve IOC geçmişini inceler ve sonunda karar, güven oranı, kanıtlar ve önerilerden oluşan bir rapor yazar.
- Alarm durumunu değiştirmek ya da watchlist'e terim eklemek gibi işlemler **sizin onayınızı bekler**. Sayfalardaki "AI, bu alarmı kapat" türünden talimatlar uygulanmaz.
- Yeni ve önem derecesi yüksek alarmlar otomatik olarak incelenir (`ANALYST_AUTO_SEVERITY`).
- Kullandığınız modelin başarısını ölçmek için: `python -m darkweb_monitor.cli analyst-eval --provider auto`

## AI sağlayıcıları ve yerel modeller (AI & Models)
- **Sağlayıcı ekle**: LM Studio, Ollama, llama.cpp server, vLLM, OpenRouter, Groq ya da OpenAI uyumlu herhangi bir adres. *Load* düğmesi modelleri listeler, *Test* düğmesi bağlantıyı dener.
- **Yerel** sağlayıcılar (localhost/LAN) ham içeriği görebilir. **Uzak** sağlayıcılara yalnızca maskelenmiş özetler gider.
- **GGUF**: Hugging Face depo adını yazın (ör. `Qwen/Qwen2.5-3B-Instruct-GGUF`), dosyayı seçip indirin. Dilerseniz dosyayı yükleyebilir ya da diskteki yolunu kaydedebilirsiniz. `LLAMACPP_MODE=managed` olduğunda uygulama `llama-server`'ı kendisi başlatır.
- **Küçük modeller**: bağlam penceresi otomatik algılanır. Uzun içerikler parçalara bölünerek gönderilir ve sonuçlar birleştirilir. "Context too long" hatası alınırsa parça küçültülüp yeniden denenir. Agent'ın geçmişi dolmak üzereyken özetlenir.

## Öğrenme (Learning)
- Model yeniden eğitilmez. Sistem **sizin onayladığınız** geri bildirimlerden öğrenir.
- Bir alarmda ya da analist raporunda **👍 Agree** ya da **👎 Disagree** düğmesine basın. Disagree derken doğru kararı ve nedenini yazın. Açıklamanız bir **ders (lesson)** olur ve benzer alarmlarda AI'a gösterilir.
- Bir watchlist terimi sürekli yanlış alarm üretiyorsa sistem bir **bastırma kuralı** önerir (ör. "phoenix" + kitap/roman → önemi düşür). Kural siz onaylayınca devreye girer.
- Düzelttiğiniz her vaka bir **regresyon testine** dönüşür. Learning sayfasındaki "Run evaluation" düğmesi ya da `analyst-eval` komutu, sistemin aynı hatayı tekrar yapıp yapmadığını ölçer.
- AI'ın kendi taslak dersleri "proposed" (önerilen) durumunda bekler. Sayfa içeriği ve AI çıktısı asla öğrenme kaynağı olmaz.
