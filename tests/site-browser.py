from pathlib import Path
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
import threading,json
from urllib.parse import urlsplit,unquote
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]
out=root/'site-checks';out.mkdir(exist_ok=True)
class Handler(SimpleHTTPRequestHandler):
 def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(root),**kwargs)
 def translate_path(self,path):
  resolved=super().translate_path(path)
  p=Path(resolved)
  if not p.exists() and p.with_suffix('.html').exists():return str(p.with_suffix('.html'))
  return resolved
 def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',18898),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
results=[]
try:
 with sync_playwright() as pw:
  browser=pw.chromium.launch(headless=True)
  for width,height,device in [(1440,1080,'desktop'),(390,844,'mobile')]:
   ctx=browser.new_context(viewport={'width':width,'height':height})
   ctx.route('https://**/*',lambda route:route.fulfill(status=200,content_type='application/json',body=json.dumps({'enforced':False,'minimum_version':'0.6.0-beta.14','auth_epoch':0})))
   page=ctx.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
   for path in ['/','/how-it-works','/mods','/beta','/update','/privacy','/terms','/verify?request='+'A'*40]:
    response=page.goto('http://127.0.0.1:18898'+path,wait_until='networkidle')
    assert response.status==200,(path,response.status)
    assert page.locator('h1').count()==1,(path,'one H1 required')
    overflow=page.evaluate('document.documentElement.scrollWidth>innerWidth+1')
    if overflow:
     page.screenshot(path=str(out/f'overflow-{device}.png'),full_page=True)
     diagnostics=page.evaluate("Array.from(document.querySelectorAll('body *')).filter(e=>e.getBoundingClientRect().right>innerWidth+1).map(e=>({tag:e.tagName,id:e.id,cls:e.className,right:e.getBoundingClientRect().right,text:e.textContent.slice(0,140)})).slice(0,20)")
     (out/f'overflow-{device}.json').write_text(json.dumps(diagnostics,indent=2))
    assert not overflow,(path,device,'horizontal overflow')
    if path in ['/','/how-it-works','/update'] or path.startswith('/verify'):
     name='home' if path=='/' else path.split('?')[0].strip('/')
     page.screenshot(path=str(out/f'{name}-{device}.png'),full_page=True)
    if path.startswith('/verify'):
     assert page.locator('#continue-button').is_enabled()
     assert 'network identifier' in page.locator('#verification-disclosure').inner_text()
    results.append({'page':path.split('?')[0],'viewport':device,'http':200,'horizontal_overflow':False})
   assert not errors,errors
   ctx.close()
  browser.close()
finally:server.shutdown()
(out/'result.json').write_text(json.dumps({'checks':results,'count':len(results),'note':'Local browser rendering with synthetic cloud policy responses. No OAuth, live viewer, moderation, or deployment tested.'},indent=2))
print('PASS',len(results),'desktop/mobile page checks; no script errors or horizontal overflow. Local rendering only.')
