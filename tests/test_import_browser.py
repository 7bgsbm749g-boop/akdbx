"""Real Chromium decoder/form check, only in the isolated synthetic fixture."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from test_target_chromium import synthetic_chromium
from test_target import isolated_x11


def test_node_extension_contracts():
    node=shutil.which('node')
    if not node:pytest.skip('Node is required for extension contract tests')
    result=subprocess.run([node,'--test',str(Path(__file__).with_name('test_browser_import.js'))],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stdout+result.stderr


@pytest.mark.parametrize('change_during_decode', [False, True])
def test_real_chromium_qr_image_to_private_form(synthetic_chromium, change_during_decode):
    _,_,cdp,session,_,_=synthetic_chromium
    assets=Path(__file__).parent.parent/'src'/'akdbx'/'import_assets'
    fixture=json.loads(Path(__file__).with_name('synthetic_qr.json').read_text())
    html='''<form action="https://private.example/totp/import?token=synthetic"><input id="images" type="file" multiple><input id="camera" type="file"><input id="manual" type="password"><input id="payloads" name="payloads" type="hidden"><p id="message"></p><button id="decode" type="button">Decode</button></form>'''
    cdp.evaluate('document.body.innerHTML='+json.dumps(html),session)
    cdp.evaluate((assets/'jsQR.js').read_text(),session)
    cdp.evaluate((assets/'import.js').read_text(),session)
    expression='''(async()=>{
      const fixture=FIXTURE;
      const changed=INVALIDATE;
      const originalDecode=Image.prototype.decode;
      let release;const gate=new Promise(resolve=>{release=resolve;});
      if(changed)Image.prototype.decode=async function(){await originalDecode.call(this);await gate;};
      const canvas=document.createElement('canvas');const scale=4;canvas.width=canvas.height=fixture.rows.length*scale;
      const ctx=canvas.getContext('2d');
      for(let y=0;y<fixture.rows.length;y++)for(let x=0;x<fixture.rows.length;x++){
        ctx.fillStyle=fixture.rows[y][x]==='1'?'black':'white';ctx.fillRect(x*scale,y*scale,scale,scale);
      }
      const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));
      const dt=new DataTransfer();dt.items.add(new File([blob],'synthetic.png',{type:'image/png'}));
      document.getElementById('images').files=dt.files;
      const reading=document.getElementById('decode').onclick();
      if(changed){
        const manual=document.getElementById('manual');
        manual.value=fixture.uri.replace(/secret=[^&]+/,'secret=JBSWY3DPEHPK3PXP');
        manual.dispatchEvent(new Event('input'));release();
      }
      await reading;Image.prototype.decode=originalDecode;
      const decoded=document.getElementById('message').textContent.includes('read privately');
      window.fetch=async(url,options)=>{window.syntheticSubmission={url,payloads:JSON.parse(options.body.get('payloads'))};return {ok:false};};
      await document.querySelector('form').onsubmit({preventDefault(){}});
      return {decoded,submission:window.syntheticSubmission,manual:document.getElementById('manual').value,files:document.getElementById('images').files.length};
    })()'''.replace('FIXTURE',json.dumps(fixture)).replace('INVALIDATE',json.dumps(change_during_decode))
    response=cdp.call('Runtime.evaluate',dict(expression=expression,awaitPromise=True,returnByValue=True),session)
    assert 'exceptionDetails' not in response
    result=response['result']['value']
    assert result['decoded'] is (not change_during_decode)
    expected=fixture['uri'].replace('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ','JBSWY3DPEHPK3PXP') if change_during_decode else fixture['uri']
    assert result['submission']['payloads']==[expected]
    assert result['manual']=='' and result['files']==0
