# DarkWeb Monitor 0.1.0 – Kısa Kullanım Kılavuzu

## Kurulum
1. `.env.example` dosyasını `.env` olarak kopyalayın.
2. Tor'u başlatın (daemon: port 9050, Tor Browser: 9150 → `TOR_PROXY_PORT=9150`).
3. İsteğe bağlı: Ollama kurup `ollama pull qwen2.5:7b` çalıştırın (yerel AI).
4. `pip install -r requirements.txt` → `python -m darkweb_monitor.cli init` → `python -m darkweb_monitor.cli serve`
5. Tarayıcıda `http://127.0.0.1:8000` adresini açın.

## İlk adımlar
- **Watchlist**: Önce alan adlarınızı, marka adınızı ve kritik e-posta adreslerinizi ekleyin. Crawler, HIBP, IntelX ve ransomware kontrolleri bu listeyi kullanır.
- **Targets**: İzleme yetkiniz olan .onion adreslerini ekleyin. Her hedef için tarama modunu seçin:
  - *Standard*: klasik, sıralı tarama
  - *Smart*: AI, linkleri watchlist'e göre önceliklendirir
  - *Agent*: AI, verdiğiniz hedefe göre adım adım hangi sayfaya gideceğine karar verir ve hedefe ulaşınca durur
- **Zamanlama**: Her hedefe "6 saatte bir", "günlük" veya cron ifadesi verebilirsiniz.
- **AI Tasks**: Her taramadan sonra AI veya kurallar yeni görevler önerir (yeniden tarama, yeni hedef, yeni watch terimi, analist incelemesi). Yeni hedefler **her zaman** sizin onayınızı bekler.
- **Intel sources**: HIBP, IntelX ve ransomware sızıntı siteleri, API anahtarları `.env` dosyasına girildiğinde otomatik çalışır.

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
