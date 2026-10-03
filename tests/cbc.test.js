// AES-CBC: the IV is the 16-byte key, nothing extra is stored in the data. Synthetic data only.
const {JSDOM}=require('jsdom');const fs=require('fs');const nc=require('crypto');const path=require('path');
const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
function make(opts={}){
  const errs=[];
  const dom=new JSDOM(html,{runScripts:'dangerously',pretendToBeVisual:true,beforeParse(w){
    w.addEventListener('error',e=>errs.push(e.message));const wc=nc.webcrypto;
    const subtle=opts.no192?{importKey:(f,k,...r)=>k.length===24?Promise.reject(new Error('192-bit AES keys are not supported')):wc.subtle.importKey(f,k,...r),encrypt:(...a)=>wc.subtle.encrypt(...a),decrypt:(...a)=>wc.subtle.decrypt(...a)}:wc.subtle;
    Object.defineProperty(w,'crypto',{value:{subtle,getRandomValues:a=>wc.getRandomValues(a)}});
    Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async()=>{}}});
    w.TextEncoder=TextEncoder;w.TextDecoder=TextDecoder;w.Uint8Array=Uint8Array;w.scrollTo=()=>{};w.Element.prototype.scrollIntoView=()=>{};w.matchMedia=()=>({matches:true});
  }});
  return {w:dom.window,d:dom.window.document,errs};
}
const wait=ms=>new Promise(r=>setTimeout(r,ms));
let pass=0,fail=0;const ok=(c,m)=>{c?pass++:fail++;console.log((c?'PASS ':'FAIL ')+m)};
// reference: Node's own AES-128-CBC with IV = key
const javaEncrypt=(secretB64,text)=>{const key=Buffer.from(secretB64,'base64');const iv=key;
  if(key.length!==16)throw new Error('key must be 16 bytes');
  const c=nc.createCipheriv('aes-'+key.length*8+'-cbc',key,iv);return Buffer.concat([c.update(text,'utf8'),c.final()]).toString('base64')};
(async()=>{
  const {w,d,errs}=make();const $=id=>d.getElementById(id);
  const run=async()=>{$('go').click();await wait(250)};
  const out=()=>$('out').textContent,isErr=()=>$('out').classList.contains('err');
  const enc=async(secret,text)=>{$('tE').click();$('data').value=text;$('key').value=secret;await run();return {err:isErr(),out:out()}};
  const dec=async(secret,b64)=>{$('tD').click();$('data').value=b64;$('key').value=secret;await run();return {err:isErr(),out:out()}};
  const SECRET=Buffer.from('sample-key-12345').toString('base64');
  // ---- interface ----
  ok($('aGCM').getAttribute('aria-selected')==='true','starts on AES-GCM');
  $('aCBC').click();
  ok($('aCBC').getAttribute('aria-selected')==='true','AES-CBC tab selected');
  ok(!d.getElementById('ivbox')&&!/\bJava\b/.test(d.body.textContent),'no IV info row and no Java wording on the page');
  ok(!d.querySelector('select')&&!d.getElementById('ivSeg')&&!d.getElementById('ivCustom'),'no dropdown and no other IV options exist');
  ok($('aadD').hidden,'AAD is hidden in AES-CBC');
  $('tE').click();ok($('lay').hidden,'the Data layout section is hidden in AES-CBC (Encrypt)');
  // ---- encrypt equals Java ----
  const plain='{\n  "id" : 100001,\n  "name" : "\u0645\u062d\u0645\u062f"\n}';
  const e1=await enc(SECRET,plain);const ref=javaEncrypt(SECRET,plain);
  ok(!e1.err&&e1.out===ref,'encrypt output is identical to the reference (AES-128-CBC, IV = key)');
  ok(Buffer.from(e1.out,'base64').length%16===0&&/IV \/ nonce  \(16 B\)  not stored in the data \(the key is the IV\)/.test($('inspTxt').textContent)&&/Auth tag  none/.test($('inspTxt').textContent),'no IV prefix; inspect explains the IV and the missing tag');
  ok(/IV not included/.test($('live').textContent),'live size line says IV not included');
  // ---- Node interop (iv = key) ----
  const key=Buffer.from('sample-key-12345');
  const dc=nc.createDecipheriv('aes-128-cbc',key,key);ok(Buffer.concat([dc.update(Buffer.from(e1.out,'base64')),dc.final()]).toString('utf8')===plain,"Node's AES-128-CBC (iv = key) decrypts the tool's output");
  const d1=await dec(SECRET,ref);ok(!d1.err&&d1.out===plain,'decrypts reference data completely (first block included)');
  ok(/AES-128-CBC/.test($('meta').textContent)&&!/IV: the key/.test($('meta').textContent)&&/no integrity check/i.test($('meta').textContent),'result chips: AES-128-CBC and the integrity warning, without the IV chip');
  // cipher given as hex, with line breaks, key with trailing newline
  const hexc=Buffer.from(ref,'base64').toString('hex');
  ok(!(await dec(SECRET,hexc)).isErr&&(await dec(SECRET,hexc)).out===plain,'cipher given as hex');
  ok((await dec(SECRET+'\n',ref.replace(/(.{40})/g,'$1\n '))).out===plain,'cipher with line breaks and key with a trailing newline');
  // key given as hex / plain text also work
  ok((await dec(key.toString('hex'),ref)).out===plain&&(await dec('sample-key-12345',ref)).out===plain,'key as hex or plain text');
  // ---- random secrets and texts ----
  const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=<>?';
  const texts=['hello','{"id":100001,"name":"Test User"}','\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645','emoji \ud83d\ude80 and \u00e9\u00e8',nc.randomBytes(40).toString('base64'),'x'.repeat(16),'y'.repeat(32),'z'.repeat(1000)];
  let same=0,back=0,N=24;
  for(let i=0;i<N;i++){let k='';const rb=nc.randomBytes(16);for(let j=0;j<16;j++)k+=chars[rb[j]%chars.length];
    const sec=Buffer.from(k).toString('base64'),text=texts[i%texts.length];
    const m=await enc(sec,text),r=javaEncrypt(sec,text);if(!m.err&&m.out===r)same++;
    const b=await dec(sec,r);if(!b.err&&b.out===text)back++;}
  ok(same===N,'encrypt: '+same+'/'+N+' random secrets and texts match the Java reference');
  ok(back===N,'decrypt: '+back+'/'+N+' Java-reference ciphers decrypt to the exact text');
  // ---- any random 16-byte key works (it does not have to be text) ----
  { let okc=0,M=20;for(let i=0;i<M;i++){const sec=nc.randomBytes(16).toString('base64'),text=texts[i%texts.length];
      const m=await enc(sec,text),r=javaEncrypt(sec,text);const b=await dec(sec,r);if(!m.err&&m.out===r&&!b.err&&b.out===text)okc++;}
    ok(okc===M,'random raw-byte keys (not valid text): '+okc+'/'+M+' encrypt and decrypt like the reference');
    const bad=Buffer.alloc(16,0xff).toString('base64');const a=await enc(bad,'x');ok(!a.err&&a.out===javaEncrypt(bad,'x'),'a key made of 0xFF bytes works too'); }
  // ---- Generate a key ----
  { $('tE').click();$('key').value='';$('gen').click();const gk=$('key').value;const gb=Buffer.from(gk,'base64');
    ok(gb.length===16&&$('keyHint').classList.contains('ok')&&/AES-128/.test($('keyHint').textContent),'AES-CBC: "Generate a key" makes a 16-byte key that is accepted');
    const m=await enc(gk,'generated key test');const b=await dec(gk,m.out);ok(!m.err&&b.out==='generated key test','a generated key encrypts and decrypts');
    $('aGCM').click();$('key').value='';$('gen').click();{const gk2=Buffer.from($('key').value,'base64');ok(gk2.length===16&&/AES-128 key/.test($('keyHint').textContent),'AES-GCM: "Generate a key" also makes a 16-byte (AES-128) key');const g=await enc($('key').value,'gcm generated');const gb=await dec($('key').value,g.out);ok(!g.err&&gb.out==='gcm generated','a generated AES-128 key works for AES-GCM');}$('aCBC').click(); }
  // ---- keys that cannot be the IV ----
  { const k32=Buffer.from('0123456789abcdef0123456789abcdef').toString('base64');
    const c32=await enc(k32,'x');ok(c32.err&&/16 bytes/.test(c32.out),'32-byte key: clear message that AES-CBC needs a 16-byte key');
    const d32=await dec(k32,Buffer.alloc(32,1).toString('base64'));ok(d32.err&&/16 bytes/.test(d32.out),'same message on decrypt');
    $('tE').click();$('key').value=k32;$('key').dispatchEvent(new w.Event('input'));ok(/16-byte key/.test($('keyHint').textContent)&&$('keyHint').classList.contains('bad'),'key hint turns red for a 32-byte key');
    $('key').value=SECRET;$('key').dispatchEvent(new w.Event('input'));ok($('keyHint').classList.contains('ok')&&/AES-128 key/.test($('keyHint').textContent),'key hint is green for a good key'); }
  // ---- error wording ----
  { const other=Buffer.from('fedcba9876543210').toString('base64');const r=await dec(other,ref);ok(r.err&&/Decryption failed/.test(r.out)&&!/\bJava\b/.test(r.out),'wrong key gives a clear decryption error');
    const r2=await dec(SECRET,Buffer.alloc(20,3).toString('base64'));ok(r2.err&&/multiple of 16/.test(r2.out)&&!/\bJava\b/.test(r2.out),'bad data length explains the multiple-of-16 rule');
    const r3=await dec(SECRET,'');ok(r3.err,'empty data gives an error'); }
  // ---- separate state per algorithm, GCM unaffected ----
  $('tE').click();$('data').value='cbc text';$('aGCM').click();ok($('data').value!=='cbc text'&&!$('aadD').hidden&&!$('lay').hidden,'GCM keeps its own inputs; AAD and the Data layout section are back');
  { const g=await enc(SECRET,'gcm again');const gb=await dec(SECRET,g.out);ok(!g.err&&gb.out==='gcm again'&&Buffer.from(g.out,'base64').length===12+9+16,'AES-GCM still works (12-byte IV + data + 16-byte tag)'); }
  $('aCBC').click();ok($('aadD').hidden&&$('lay').hidden,'AAD and the Data layout section are hidden again in AES-CBC');
  // ---- the Inspect report has the same format for AES-GCM and AES-CBC ----
  { const shape=()=>$('inspTxt').textContent.split('\n').map(l=>{const m=l.match(/^(AES-128-(?:GCM|CBC)|Total|IV \/ nonce|Ciphertext|Auth tag|Hex:|Base64:|AAD)/);return m?m[1].replace(/^AES-128-.*/,'HEADER'):(l.trim()===''?'':'?')}).join('|');
    $('aCBC').click();await enc(SECRET,'same format check');const cbcShape=shape();const cbcText=$('inspTxt').textContent;
    $('aGCM').click();await enc(SECRET,'same format check');const gcmShape=shape();const gcmText=$('inspTxt').textContent;
    ok(cbcShape===gcmShape&&!/\?/.test(cbcShape),'Inspect report: identical sections, order and labels for AES-GCM and AES-CBC');
    ok(/^AES-128-CBC, key read as Base64/.test(cbcText)&&/^AES-128-GCM, key read as Base64/.test(gcmText),'both reports start with the same "AES-128-xxx, key read as Base64" line');
    ok(/AAD: not used/.test(cbcText)&&/AAD: none set/.test(gcmText),'AAD line present in both ("not used" for AES-CBC)'); }
  // ---- Safari-like browser without AES-192 ----
  { const s=make({no192:true});const $$=id=>s.d.getElementById(id);$$('aCBC').click();$$('tE').click();$$('data').value='x';$$('key').value='abcdefghijklmnopqrstuvwx';$$('go').click();await wait(250);
    ok($$('out').classList.contains('err'),'24-byte key in AES-CBC gives a clear error'); }
  ok(errs.length===0,'no script errors ('+errs.join('|')+')');
  console.log(`\n${pass} passed, ${fail} failed`);process.exit(fail?1:0);
})();
