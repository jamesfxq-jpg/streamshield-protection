from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlsplit,unquote
import re,json
root=Path(__file__).resolve().parents[1]
class Page(HTMLParser):
 def __init__(self,text):
  super().__init__();self.ids=[];self.links=[];self.h1=0;self.form_names=[];self.feed(text)
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'id' in a:self.ids.append(a['id'])
  if tag=='h1':self.h1+=1
  for attr in ['href','src']:
   if attr in a:self.links.append(a[attr])
  if 'name' in a:self.form_names.append(a['name'])
pages={p.name:Page(p.read_text()) for p in root.glob('*.html')}
for name,p in pages.items():
 assert len(p.ids)==len(set(p.ids)),(name,'duplicate IDs')
 assert p.h1==1,(name,'expected one H1')
 text=(root/name).read_text()
 assert not re.search(r'0\.6\.0-beta\.(12|13)|BETA\.(12|13)|Beta (12|13)',text),(name,'stale release wording')
 for url in p.links:
  u=urlsplit(url)
  if u.scheme or u.netloc or not u.path and not u.fragment:continue
  file=root/('index.html' if u.path=='/' else (unquote(u.path).lstrip('/') or name))
  if not file.exists() and not file.suffix:file=file.with_suffix('.html')
  if file==root:file=root/'index.html'
  assert file.exists(),(name,url,'missing local target')
  if u.fragment and file.suffix=='.html':assert u.fragment in pages[file.name].ids,(name,url,'missing anchor')
form=pages['beta.html']
for field in ['streamshield_version','summary','actual_result','beta_acknowledged','company_website']:
 assert field in form.form_names,(field,'feedback field was lost')
assert 'network identifier' in (root/'verify.html').read_text()
assert 'first-party browser token' in (root/'verify.html').read_text()
assert 'name="consent" value="yes"' in (root/'verify.html').read_text()
assert 'disabled' in (root/'verify.html').read_text()
manifest=json.loads((root/'release.json').read_text())
assert manifest['version']=='0.6.0-beta.14'
assert manifest['sha256'] in (root/'index.html').read_text()
print('PASS',len(pages),'HTML pages: unique IDs, H1, local targets, anchors, release consistency, feedback fields and visible consent.')
