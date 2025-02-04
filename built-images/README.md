# **Dark-Watcher**  
**Automated Dark Web Monitoring and Footprinting System with AI-Driven Vulnerability Scoring**  

## **Overview**  
Dark-Watcher is a comprehensive system designed to monitor the dark web for hidden services, extract intelligence from open sources, and provide AI-driven vulnerability scoring. It enhances security by identifying threats, tracking domain activities, and analyzing risk levels using advanced data processing techniques.  

## **Features**  

- **Dark Web Crawling** – Automatically discovers new hidden services.  
- **Clear Web Intelligence Gathering** – Extracts onion service references from open web sources.  
- **Elasticsearch Integration** – Supports full-text search and indexing of collected data.  
- **Clone Site Detection** – Identifies duplicate darknet sites and potential phishing threats.  
- **Credential & Asset Discovery** – Extracts email addresses and Bitcoin wallets from dark web pages.  
- **Onion Link Analysis** – Maps inbound and outbound connections between hidden services.  
- **Service Availability Tracking** – Monitors the online/offline status of onion domains.  
- **Port Scanning** – Identifies exposed services on hidden servers.  
- **Intelligent URL Analysis** – Detects patterns in URLs to flag suspicious content.  
- **Language Detection** – Categorizes dark web content based on language.  
- **Fuzzy Matching for Clone Detection** – Uses AI-powered similarity analysis for clone detection (requires Elasticsearch).  

## **System Components**  

### **1. Elasticsearch**  
- Runs as a two-node cluster for high availability and load balancing.  
- Stores and indexes scraped page data.  

### **2. Kibana**  
- Accessible on port `5601`.  
- Provides visualization and search capabilities for Elasticsearch data.  

### **3. MySQL**  
- Stores domain metadata, URLs, Bitcoin addresses, and extracted intelligence.  

### **4. TOR Proxy**  
- Enables access to onion services.  
- Deploys 10 proxy containers, managed by HAProxy for traffic distribution.  

### **5. Scraper**  
- Extracts domain lists from MySQL.  
- Crawls and harvests new onion pages through TOR proxies.  
- Stores extracted data in both Elasticsearch and MySQL.  
- Built on the Python **Scrapy** framework.  

## **Installation**  

### **1. Deploy with Docker Compose**  
```bash
docker-compose pull
docker-compose up -d
```

### **2. Run the Dark Web Scraper**  
```bash
docker run -d --name darkweb-search-engine-onion-crawler --cpus="0.5" --restart=always --network=built-images_default dapperblondie/scraper_crawler_complete /opt/torscraper/scripts/start_onion_scrapy.sh
```

### **3. Migrate Elasticsearch Data**  
```bash
docker exec darkweb-search-engine-onion-crawler /opt/torscraper/scripts/elasticsearch_migrate.sh
```

### **4. Push Onion List for Crawling**  
```bash
docker exec -d darkweb-search-engine-onion-crawler /opt/torscraper/scripts/push_list.sh /opt/torscraper/onions_list/onions.txt
```

## **Data Sources**  
Dark-Watcher utilizes multiple sources, including:  
- [Ahmia.fi Onions List](https://ahmia.fi/onions/)  

