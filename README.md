# Dark-Watcher

Dark-Watcher is a comprehensive cybersecurity system designed to monitor the dark web for hidden services, extract intelligence from open sources, and provide AI-driven vulnerability scoring. It enhances security by identifying threats, tracking domain activities, and analyzing risk levels using advanced data processing techniques. The system consists of two primary components: **Dark Web Scraper, Data Storage and visualization** and **Footprinting Tool**.

---
## **1. Dark Web Scraper, Data Storage and visualization**
This component is responsible for crawling the dark web, extracting data from hidden services, and visualizing the collected intelligence through Kibana dashboards.

### **Features**
- **Dark Web Crawling**: Crawls the darknet to discover new hidden services.
- **Data Aggregation**: Collects data from various clearnet sources related to hidden services.
- **Elasticsearch Integration**: Supports full-text search using Elasticsearch for efficient data retrieval.
- **Domain Clone Detection**: Identifies duplicate or cloned sites using fuzzy detection algorithms.
- **Port Scanning**: Detects open ports on hidden services.
- **Data Enrichment**:
  - Finds **SSH fingerprints** across hidden services.
  - Extracts **email addresses** from hidden services.
  - Detects **Bitcoin wallet addresses** linked to hidden services.
- **Link Analysis**: Identifies incoming/outgoing links to and from onion domains.
- **Status Monitoring**: Provides up-to-date status of active/inactive hidden services.
- **Interesting Path Discovery**: Searches for common yet significant URL paths to detect hidden or vulnerable pages.
- **Language Detection**: Automatically detects and classifies language content on hidden services.
- **Kibana dashboard**: Provides a comprehensive view of the collected data, including visualizations of domain activities, risk levels, and other relevant metrics.

### **Components**
#### **Elasticsearch**
- A two-node Elasticsearch cluster is deployed to provide high availability (HA) and load balancing.
- Stores and indexes scraped page data for fast retrieval and analysis.

#### **Kibana**
- Runs on port **5601** and provides a user-friendly dashboard to visualize and analyze the indexed data.

#### **Web Interface**
- Provides a domain search engine accessible via port **7000**.

#### **MySQL Database**
- Stores structured data such as domain details, page URLs, Bitcoin addresses, and metadata.

#### **TOR Proxy**
- Enables anonymous access to dark web content via **10 Tor proxy containers**.
- **HAProxy** is used for traffic distribution, ensuring stability and load balancing.

#### **Scraper**
- Fetches a list of domains from MySQL, scrapes hidden services, and extracts new domains.
- Stores retrieved data in both Elasticsearch and MySQL.
- Built on the **Python Scrapy framework**.

### **Installation**
#### **1. Deploy with Docker Compose**  
```bash
cd built-images
docker-compose pull
docker-compose up -d
```
#### **2. Run the Dark Web Scraper**  
```bash
docker run -d --name darkweb-search-engine-onion-crawler --cpus="0.5" --restart=always --network=built-images_default dapperblondie/scraper_crawler_complete /opt/torscraper/scripts/start_onion_scrapy.sh
```
#### **3. Migrate Elasticsearch Data**  
```bash
docker exec darkweb-search-engine-onion-crawler /opt/torscraper/scripts/elasticsearch_migrate.sh
```
#### **4. Push Onion List for Crawling**  
```bash
docker exec -d darkweb-search-engine-onion-crawler /opt/torscraper/scripts/push_list.sh /opt/torscraper/onions_list/onions.txt
```

---

## **2. Footprinting Tool & AI Vulnerability Scoring**
The footprinting tool automates the process of gathering intelligence on domains and provides AI-driven vulnerability assessments.

### **Features**
- **Subdomain Enumeration**: Uses tools like **subfinder** to gather all subdomains of a given target.
- **IP Resolution**: Resolves subdomains to their respective IP addresses.
- **Port Scanning**: Detects open ports using **naabu**.
- **Technology Stack Detection**: Identifies web frameworks, server details, and security configurations using **httpx**.
- **Security Headers Analysis**: Examines HTTP headers for security weaknesses.
- **Data Visualization**:
  - **Network Graphs** using **Pyvis** to visualize subdomain relationships.
  - **Pie Charts** using **Plotly** to display open port distributions.
- **Historical Breach Data**: Fetches past breach information from external sources like **hackedlist.io**.
- **AI Vulnerability Analysis**:
  - Aggregates collected data and sends it to an **ollama**.
  - Receives structured JSON responses with **risk scores, vulnerability explanations, and remediation suggestions**.
- **Flask Web Interface**: Provides an intuitive web interface for launching scans and viewing analytics.

### **Installation**
#### **1. Deploy Footprinting Tool**  
```bash
cd analyzer
pip install -r requirement.txt
python main.py
```

