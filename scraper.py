import asyncio
import tkinter as tk
from tkinter import scrolledtext
import aiohttp
from playwright.async_api import async_playwright
import logging
from bs4 import BeautifulSoup
import re
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(filename='scraper.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Database setup
Base = declarative_base()
engine = create_engine('sqlite:///vulnerabilities.db')
Session = sessionmaker(bind=engine)

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    product_name = Column(String)
    product_version = Column(String)
    oem_name = Column(String)
    severity_level = Column(String)
    vulnerability = Column(String)
    mitigation_strategy = Column(String)
    published_date = Column(DateTime)
    unique_id = Column(String, unique=True)

Base.metadata.create_all(engine)

class VulnerabilityScraper:
    def __init__(self, urls, email_recipients):
        self.urls = urls
        self.email_recipients = email_recipients
        self.vulnerabilities = []

    async def scrape_vulnerabilities(self):
        logging.info(f"Starting to scrape {len(self.urls)} URLs")
        async with aiohttp.ClientSession() as session:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                tasks = [self.scrape_url(url, browser, session) for url in self.urls]
                await asyncio.gather(*tasks)
                await browser.close()
        logging.info(f"Finished scraping. Found {len(self.vulnerabilities)} vulnerabilities")

    async def scrape_url(self, url, browser, session):
        try:
            logging.info(f"Scraping URL: {url}")
            page = await browser.new_page()
            await page.goto(url, wait_until="networkidle")
            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')

            vulnerabilities = soup.find_all('div', class_='vulnerability')
            logging.info(f"Found {len(vulnerabilities)} vulnerability divs on {url}")
            
            for vuln in vulnerabilities:
                try:
                    severity = vuln.find('span', class_='severity').text
                    if severity.lower() in ['critical', 'high']:
                        self.vulnerabilities.append({
                            'product_name': vuln.find('h2', class_='product-name').text,
                            'product_version': vuln.find('span', class_='version').text or 'NA',
                            'oem_name': self.extract_oem_name(url),
                            'severity_level': severity,
                            'vulnerability': vuln.find('p', class_='description').text,
                            'mitigation_strategy': vuln.find('a', class_='mitigation')['href'],
                            'published_date': datetime.strptime(vuln.find('span', class_='date').text, '%Y-%m-%d'),
                            'unique_id': vuln.find('span', class_='cve').text
                        })
                        logging.info(f"Added vulnerability: {self.vulnerabilities[-1]['unique_id']}")
                except Exception as e:
                    logging.error(f"Error processing vulnerability on {url}: {str(e)}")
            
            await self.save_to_database()
            
        except Exception as e:
            logging.error(f"Error scraping {url}: {str(e)}")

    def extract_oem_name(self, url):
        match = re.search(r'https?://(?:www\.)?([^/]+)', url)
        return match.group(1) if match else 'Unknown'

    async def save_to_database(self):
        session = Session()
        for vuln in self.vulnerabilities:
            try:
                new_vuln = Vulnerability(**vuln)
                session.add(new_vuln)
                session.commit()
            except Exception as e:
                session.rollback()
                logging.error(f"Error saving vulnerability to database: {str(e)}")
        session.close()

    async def send_email(self):
        if not self.vulnerabilities:
            logging.info("No vulnerabilities found, no email sent.")
            return

        for vuln in self.vulnerabilities:
            subject = f"New {vuln['severity_level']} Vulnerability: {vuln['product_name']}"
            body = f"""
            Product Name: {vuln['product_name']}
            Product Version: {vuln['product_version']}
            OEM name: {vuln['oem_name']}
            Severity Level: {vuln['severity_level']}
            Vulnerability: {vuln['vulnerability']}
            Mitigation Strategy: {vuln['mitigation_strategy']}
            Published Date: {vuln['published_date']}
            Unique ID: {vuln['unique_id']}
            """
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = os.getenv('EMAIL_FROM')
            msg['To'] = ", ".join(self.email_recipients)
            
            try:
                with smtplib.SMTP_SSL(os.getenv('SMTP_SERVER'), int(os.getenv('SMTP_PORT'))) as server:
                    server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASSWORD'))
                    server.send_message(msg)
                logging.info(f"Email sent for vulnerability {vuln['unique_id']}")
            except Exception as e:
                logging.error(f"Error sending email: {str(e)}")

class VulnerabilityScraperGUI:
    def __init__(self, master):
        self.master = master
        master.title("Vulnerability Scraper")

        self.url_label = tk.Label(master, text="Enter URLs (one per line):")
        self.url_label.pack()

        self.url_text = scrolledtext.ScrolledText(master, height=5)
        self.url_text.pack()

        self.email_label = tk.Label(master, text="Enter email recipients (comma-separated):")
        self.email_label.pack()

        self.email_entry = tk.Entry(master, width=50)
        self.email_entry.pack()

        self.scrape_button = tk.Button(master, text="Scrape Vulnerabilities", command=self.scrape)
        self.scrape_button.pack()

        self.result_text = scrolledtext.ScrolledText(master, height=10)
        self.result_text.pack()

    def scrape(self):
        urls = self.url_text.get("1.0", tk.END).splitlines()
        emails = self.email_entry.get().split(',')
        
        scraper = VulnerabilityScraper(urls, emails)
        
        async def run_scraper():
            await scraper.scrape_vulnerabilities()
            await scraper.send_email()
            self.result_text.insert(tk.END, f"Scraped {len(scraper.vulnerabilities)} vulnerabilities and attempted to send emails.\n")
            self.result_text.insert(tk.END, "Check the log file for more details.\n")
        
        # Run the async function in a separate thread
        self.master.after(0, self.run_async_function, run_scraper)

    def run_async_function(self, async_function):
        asyncio.run(async_function())

if __name__ == "__main__":
    root = tk.Tk()
    gui = VulnerabilityScraperGUI(root)
    root.mainloop()