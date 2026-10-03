// AES-CBC: the IV is always the key (Java: IvParameterSpec(key)). Synthetic data only.
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
// reference = the Java code step by step
const javaEncrypt=(secretB64,text)=>{const key=Buffer.from(secretB64,'base64');const iv=Buffer.from(key.toString('utf8'),'utf8');
  if(iv.length!==16)throw new Error('Wrong IV length: must be 16 bytes long');
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
  ok(!d.getElementById('ivbox')&&!/Same as the key \(Java style\)/.test(d.body.textContent),'the IV info row is gone from the page');
  ok(!d.querySelector('select')&&!d.getElementById('ivSeg')&&!d.getElementById('ivCustom'),'no dropdown and no other IV options exist');
  ok($('aadD').hidden,'AAD is hidden in AES-CBC');
  $('tE').click();ok($('lay').hidden,'the Data layout section is hidden in AES-CBC (Encrypt)');
  // ---- encrypt equals Java ----
  const plain='{\n  "id" : 100001,\n  "name" : "\u0645\u062d\u0645\u062f"\n}';
  const e1=await enc(SECRET,plain);const ref=javaEncrypt(SECRET,plain);
  ok(!e1.err&&e1.out===ref,'encrypt output is identical to the Java reference');
  ok(Buffer.from(e1.out,'base64').length%16===0&&/not stored in the data \(taken from the key\)/.test($('inspTxt').textContent)&&/Integrity: none/.test($('inspTxt').textContent),'no IV prefix; inspect explains the IV and the missing integrity check');
  ok(/IV not included/.test($('live').textContent),'live size line says IV not included');
  // ---- Node interop (iv = key) ----
  const key=Buffer.from('sample-key-12345');
  const dc=nc.createDecipheriv('aes-128-cbc',key,key);ok(Buffer.concat([dc.update(Buffer.from(e1.out,'base64')),dc.final()]).toString('utf8')===plain,"Node's AES-128-CBC (iv = key) decrypts the tool's output");
  const d1=await dec(SECRET,ref);ok(!d1.err&&d1.out===plain,'decrypts Java-style data completely (first block included)');
  ok(/AES-128-CBC/.test($('meta').textContent)&&!/IV: the key/.test($('meta').textContent)&&/no integrity check/i.test($('meta').textContent),'result chips: AES-128-CBC and the integrity warning, without the IV chip');
  // cipher given as hex, with line breaks, key with trailing newline
  const hexc=Buffer.from(ref,'base64').toString('hex');
  ok(!(await dec(SECRET,hexc)).isErr&&(await dec(SECRET,hexc)).out===plain,'cipher given as hex');
  ok((await dec(SECRET+'\n',ref.replace(/(.{40})/g,'$1\n '))).out===plain,'cipher with line breaks and key with a trailing newline');
  // key given as hex / plain text also work
  ok((await dec(key.toString('hex'),ref)).out===plain&&(await dec('sample-key-12345',ref)).out===plain,'key as hex or plain text');
  // ---- random Java-style secrets and texts ----
  const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=<>?';
  const texts=['hello','{"id":100001,"name":"Test User"}','\u0645\u0631\u062d\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645','emoji \ud83d\ude80 and \u00e9\u00e8',nc.randomBytes(40).toString('base64'),'x'.repeat(16),'y'.repeat(32),'z'.repeat(1000)];
  let same=0,back=0,N=24;
  for(let i=0;i<N;i++){let k='';const rb=nc.randomBytes(16);for(let j=0;j<16;j++)k+=chars[rb[j]%chars.length];
    const sec=Buffer.from(k).toString('base64'),text=texts[i%texts.length];
    const m=await enc(sec,text),r=javaEncrypt(sec,text);if(!m.err&&m.out===r)same++;
    const b=await dec(sec,r);if(!b.err&&b.out===text)back++;}
  ok(same===N,'encrypt: '+same+'/'+N+' random secrets and texts match the Java reference');
  ok(back===N,'decrypt: '+back+'/'+N+' Java-reference ciphers decrypt to the exact text');
  // ---- valid multi-byte UTF-8 key (16 bytes) ----
  { const mb=Buffer.from('abcd\u00e9fghijklm12','utf8');ok(mb.length===16,'(multi-byte key is 16 bytes)');
    const sec=mb.toString('base64');const m=await enc(sec,'multi-byte');ok(!m.err&&m.out===javaEncrypt(sec,'multi-byte'),'valid multi-byte UTF-8 key matches Java'); }
  // ---- keys Java rejects ----
  { const bad=Buffer.alloc(16,0xff).toString('base64');let jf=false;try{javaEncrypt(bad,'x')}catch(e){jf=/Wrong IV length/.test(e.message)}
    const a=await enc(bad,'x'),b=await dec(bad,Buffer.alloc(32,1).toString('base64'));
    ok(jf&&a.err&&/valid UTF-8/.test(a.out)&&/Java would fail/.test(a.out),'16 bytes that are not valid UTF-8: Java fails and the tool explains (encrypt)');
    ok(b.err&&/valid UTF-8/.test(b.out),'same explanation on decrypt');
    $('tE').click();$('key').value=bad;$('key').dispatchEvent(new w.Event('input'));ok(/valid UTF-8/.test($('keyHint').textContent)&&$('keyHint').classList.contains('bad'),'key hint turns red: key must be valid UTF-8 text');
    const k32=Buffer.from('0123456789abcdef0123456789abcdef').toString('base64');let j2=false;try{javaEncrypt(k32,'x')}catch(e){j2=true}
    const c32=await enc(k32,'x');ok(j2&&c32.err&&/16 bytes/.test(c32.out),'32-byte key: Java fails, the tool explains');
    $('key').value=SECRET;$('key').dispatchEvent(new w.Event('input'));ok($('keyHint').classList.contains('ok')&&/AES-128 key/.test($('keyHint').textContent),'key hint is green for a good key'); }
  { const k32b=Buffer.from('0123456789abcdef0123456789abcdef').toString('base64');$('key').value=k32b;$('key').dispatchEvent(new w.Event('input'));ok(/16-byte key/.test($('keyHint').textContent)&&$('keyHint').classList.contains('bad'),'key hint says AES-CBC needs a 16-byte key for a 32-byte key');$('key').value=SECRET;$('key').dispatchEvent(new w.Event('input')); }
  // ---- Java-style exception wording ----
  { const other=Buffer.from('fedcba9876543210').toString('base64');const r=await dec(other,ref);ok(r.err&&/BadPaddingException/.test(r.out),'wrong key reports BadPaddingException');
    const r2=await dec(SECRET,Buffer.alloc(20,3).toString('base64'));ok(r2.err&&/IllegalBlockSizeException/.test(r2.out),'bad data length reports IllegalBlockSizeException');
    const r3=await dec(SECRET,'');ok(r3.err,'empty data gives an error'); }
  // ---- separate state per algorithm, GCM unaffected ----
  $('tE').click();$('data').value='cbc text';$('aGCM').click();ok($('data').value!=='cbc text'&&!$('aadD').hidden&&!$('lay').hidden,'GCM keeps its own inputs; AAD and the Data layout section are back');
  { const g=await enc(SECRET,'gcm again');const gb=await dec(SECRET,g.out);ok(!g.err&&gb.out==='gcm again'&&Buffer.from(g.out,'base64').length===12+9+16,'AES-GCM still works (12-byte IV + data + 16-byte tag)'); }
  $('aCBC').click();ok($('aadD').hidden&&$('lay').hidden,'AAD and the Data layout section are hidden again in AES-CBC');
  // ---- Safari-like browser without AES-192 ----
  { const s=make({no192:true});const $$=id=>s.d.getElementById(id);$$('aCBC').click();$$('tE').click();$$('data').value='x';$$('key').value='abcdefghijklmnopqrstuvwx';$$('go').click();await wait(250);
    ok($$('out').classList.contains('err'),'24-byte key in AES-CBC gives a clear error'); }
  ok(errs.length===0,'no script errors ('+errs.join('|')+')');
  console.log(`\n${pass} passed, ${fail} failed`);process.exit(fail?1:0);
})();
