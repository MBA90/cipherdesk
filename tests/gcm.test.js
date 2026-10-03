const {JSDOM}=require('jsdom');const fs=require('fs');const nc=require('crypto');
const path=require('path');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
function make(opts={}){
  const copied=[],errs=[];
  const dom=new JSDOM(html,{runScripts:'dangerously',pretendToBeVisual:true,beforeParse(w){
    w.addEventListener('error',e=>errs.push(e.message));
    const wc=nc.webcrypto;
    const subtle=opts.no192?{importKey:(f,k,...r)=>k.length===24?Promise.reject(new Error('192-bit AES keys are not supported')):wc.subtle.importKey(f,k,...r),encrypt:(...a)=>wc.subtle.encrypt(...a),decrypt:(...a)=>wc.subtle.decrypt(...a)}:wc.subtle;
    Object.defineProperty(w,'crypto',{value:{subtle,getRandomValues:a=>wc.getRandomValues(a)}});
    Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async t=>{copied.push(t)}}});
    w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;w.Uint8Array=Uint8Array;w.scrollTo=()=>{};
    w.Element.prototype.scrollIntoView=()=>{};
    w.matchMedia=()=>({matches:true});
  }});
  return {w:dom.window,d:dom.window.document,copied,errs};
}

/* ---- synthetic fixtures (no real data) ---- */
const SAMPLE=JSON.stringify({arabicCustomerName:"\u0645\u062d\u0645\u062f \u0623\u062d\u0645\u062f",englishCustomerName:"JOHN Q SAMPLE",birthDate:"1990-01-01",email:"user@example.com",pod:null,nationalId:"000000000000000",category:"TEST"},null,2);
function gcmBlob(keyB64,text,aad){const key=Buffer.from(keyB64,'base64'),iv=nc.randomBytes(12);const c=nc.createCipheriv('aes-'+key.length*8+'-gcm',key,iv);if(aad)c.setAAD(Buffer.from(aad));const ct=Buffer.concat([c.update(text,'utf8'),c.final()]);return Buffer.concat([iv,ct,c.getAuthTag()]).toString('base64')}
const wait=ms=>new Promise(r=>setTimeout(r,ms));
let pass=0,fail=0;
const ok=(c,m)=>{c?pass++:fail++;console.log((c?'PASS ':'FAIL ')+m)};
(async()=>{
  const {w,d,copied,errs}=make();const $=id=>d.getElementById(id);
  const run=async()=>{$('go').click();await wait(250)};
  const KEY='c2FtcGxlLWtleS0xMjM0NQ==',PK='Sample!Key#2026$';
  const out=()=>$('out').textContent, isErr=()=>$('out').classList.contains('err');
  ok($('res').classList.contains('empty'),'result panel empty at start');
  ok($('tD').getAttribute('aria-selected')==='true'&&$('go').textContent==='Decrypt','starts on Decrypt');
  // validations
  await run();ok(isErr()&&/Paste the encrypted data/.test(out()),'Decrypt empty data message');
  $('data').value='abc!!';await run();ok(/valid Base64/.test(out()),'invalid Base64 message');
  $('data').value='QUJD';await run();ok(/too short/.test(out()),'too-short message');
  $('data').value='QUJD'.repeat(10);await run();ok(/Enter a key/.test(out()),'missing key message');
  $('key').value='short';await run();ok(/16, 24 or 32 bytes/.test(out()),'bad key length message');
  ok($('go').disabled===false&&$('go').textContent==='Decrypt','button restored after errors');
  // encrypt round trip with both keys
  const plain=SAMPLE;
  for(const [k,aad] of [[KEY,'1700000000'],[PK,''],['00112233445566778899aabbccddeeff','x']]){
    w.document.getElementById('tE').click();$('data').value=plain;$('key').value=k;$('aad').value=aad;await run();
    const c=out();ok(!isErr()&&c.length>20&&$('olabel').textContent==='Encrypted data (Base64)','Encrypt ok key='+k.slice(0,6));
    ok(!$('insp').hidden&&/Total: \d+ bytes/.test($('inspTxt').textContent)&&/Hex:/.test($('inspTxt').textContent),'Inspect report shown');
    if(k.length===32)ok(/key read as hex/.test($('inspTxt').textContent)&&/AES-128/.test($('inspTxt').textContent),'32-char hex key read as hex (AES-128)');
    $('tD').click();$('data').value=c;$('key').value=k;$('aad').value=aad;await run();
    ok(!isErr()&&out()===plain,'Decrypt round trip exact text key='+k.slice(0,6));
  }
  // exact python interoperability for hex key
  $('tE').click();$('data').value='interop test';$('key').value='00112233445566778899aabbccddeeff';$('aad').value='';await run();
  const raw=Buffer.from(out(),'base64');
  const d2=nc.createDecipheriv('aes-128-gcm',Buffer.from('00112233445566778899aabbccddeeff','hex'),raw.subarray(0,12));d2.setAuthTag(raw.subarray(raw.length-16));
  ok(Buffer.concat([d2.update(raw.subarray(12,raw.length-16)),d2.final()]).toString()==='interop test','Node AES-128-GCM decrypts tool output (interop)');
  // wrong AAD / wrong key messages
  $('tE').click();$('data').value='aad test';$('key').value='00112233445566778899aabbccddeeff';$('aad').value='42';await run();const cipher=out();
  $('tD').click();$('data').value=cipher;$('key').value='00112233445566778899aabbccddeeff';$('aad').value='1';await run();ok(isErr()&&/Check the key and the AAD/.test(out()),'wrong AAD message (AAD set)');
  $('aad').value='';await run();ok(isErr()&&/encrypted with an AAD/.test(out()),'wrong/missing AAD hint (no AAD)');
  ok(!$('copyIn').hidden===false,'copy button hidden on error');
  // generated ciphers in three JSON styles
  const A=gcmBlob(KEY,SAMPLE.split('\n').join('\r\n')),B=gcmBlob(KEY,SAMPLE),C=gcmBlob(KEY,SAMPLE.split('": ').join('" : '));
  for(const [n,b] of [['A',A],['B',B],['C',C]]){$('data').value=b;$('key').value=KEY;$('aad').value='';await run();ok(!isErr()&&/CustomerName/.test(out())&&$('olabel').textContent==='JSON','Decrypt generated GCM cipher '+n+' ('+$('meta').textContent+')')}
  // hex cipher input
  $('data').value=Buffer.from(C,'base64').toString('hex');await run();ok(!isErr()&&/CustomerName/.test(out()),'Decrypt cipher given as hex');
  // whitespace/newlines in cipher
  $('data').value=C.replace(/(.{60})/g,'$1\n  ');await run();ok(!isErr()&&/CustomerName/.test(out()),'Decrypt cipher with line breaks');
  // key with trailing newline
  $('data').value=C;$('key').value=KEY+'\n';await run();ok(!isErr(),'key with trailing newline');
  // binary output
  { $('tE').click();$('data').value='';}
  // persistence per tab
  $('tE').click();$('data').value='tab E text';$('key').value=KEY;await run();const eRes=out();
  $('tD').click();ok($('data').value!=='tab E text','inputs not shared between tabs');
  $('tE').click();ok($('data').value==='tab E text'&&out()===eRes&&!$('res').classList.contains('empty'),'Encrypt tab keeps input and result');
  $('tD').click();ok(!$('res').classList.contains('empty')&&/CustomerName/.test(out()),'Decrypt tab keeps its result');
  // copy
  copied.length=0;$('copyIn').click();await wait(80);ok(copied.length===1&&copied[0]===out(),'Copy button copies result');
  ok(/Copied/.test($('copyIn').textContent),'Copy button shows Copied');
  // clear
  $('clr').click();ok($('res').classList.contains('empty')&&$('data').value===''&&$('key').value==='','Clear all clears inputs and result (this tab)');
  $('tE').click();ok(!$('res').classList.contains('empty'),'Clear does not touch other tab');
  // generate key
  $('gen').click();ok($('key').value.length===44&&$('key').type==='text','Generate key creates 256-bit Base64');
  // AAD UI
  $('clr').click();$('tsnow').click();ok(/^\d{10}$/.test($('aad').value)&&$('aadD').open&&$('aadBadge').classList.contains('on'),'Use current time sets Unix seconds, opens AAD');
  // layout panel
  ok(!$('lay').hidden,'Layout panel on Encrypt');$('tD').click();ok($('lay').hidden,'Layout panel hidden on Decrypt');
  $('tE').click();$('layMore').click();ok(!$('liMore').hidden,'Show details expands');
  // keyboard
  $('data').value='kbd';$('key').value=KEY;$('aad').value='';
  d.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Enter',ctrlKey:true,bubbles:true}));await wait(250);
  ok(!isErr()&&out().length>20,'Ctrl+Enter runs');
  ok(errs.length===0,'No script errors ('+errs.join('|')+')');
  // Safari-like no AES-192
  { const s=make({no192:true});const $$=id=>s.d.getElementById(id);
    $$('data').value=C;$$('key').value=KEY;$$('go').click();await wait(300);
    ok(!$$('out').classList.contains('err')&&/CustomerName/.test($$('out').textContent),'Browser without AES-192 still decrypts Base64 key');
    $$('key').value='abcdefghijklmnopqrstuvwx';$$('go').click();await wait(300);
    ok($$('out').classList.contains('err')&&/AES-192/.test($$('out').textContent),'24-byte plain key gives clear AES-192 message');
  }
  // ---- final polish: keyboard + accessibility ----
  { const s=make();const $$=id=>s.d.getElementById(id);const kd=(el,key)=>el.dispatchEvent(new s.w.KeyboardEvent('keydown',{key,bubbles:true}));
    ok($$('tD').tabIndex===0&&$$('tE').tabIndex===-1,'roving tabindex: Decrypt tab focusable, Encrypt not');
    kd($$('tD'),'ArrowLeft');ok($$('tE').getAttribute('aria-selected')==='true','ArrowLeft moves to Encrypt');
    ok($$('tE').tabIndex===0&&$$('tD').tabIndex===-1,'tabindex follows selection');
    kd($$('tE'),'ArrowRight');ok($$('tD').getAttribute('aria-selected')==='true','ArrowRight moves back to Decrypt');
    kd($$('aGCM'),'End');ok($$('aCBC').getAttribute('aria-selected')==='true','End key selects last algorithm tab (AES-CBC)');
    kd($$('aCBC'),'Home');ok($$('aGCM').getAttribute('aria-selected')==='true','Home key selects first algorithm tab (AES-GCM)');
    ok($$('out').tabIndex===0&&$$('out').getAttribute('role')==='region'&&$$('inspTxt').tabIndex===0,'result regions are keyboard focusable');
    ok($$('aGCM').getAttribute('aria-controls')==='form'&&$$('tE').getAttribute('aria-controls')==='form','tabs reference the panel');
    ok(/dark/.test(s.d.documentElement.dataset.theme),'dark is the default theme');
    $$('themeBtn').click();ok(s.d.documentElement.dataset.theme==='light','theme button switches to light');
    ok(!s.errs.length,'no script errors in a11y checks');
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail?1:0);
})();
