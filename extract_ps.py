import requests
from bs4 import BeautifulSoup
import json

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
r = requests.get('https://www.sih.gov.in/sih2026PS', headers=headers)
soup = BeautifulSoup(r.text, 'html.parser')

# In SIH pages, problem statements are usually in a table (like id="dataTable") or in tr elements
# Let's just find the text "SIH26156" and get its parent elements.

element = soup.find(string=lambda text: text and 'SIH26156' in text)
if element:
    parent = element.find_parent('tr')
    if not parent:
        parent = element.find_parent('table')
    if not parent:
        parent = element.find_parent('div', class_='ps-box') # or something similar

    if parent:
        print("Found parent element.")
        # print the text of all child elements
        for i, child in enumerate(parent.stripped_strings):
            print(f"{i}: {child}")
    else:
        print("Found text, but no suitable parent.")
else:
    print("Not found via BeautifulSoup")
