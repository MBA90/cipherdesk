const {spawnSync}=require('child_process');const path=require('path');
const files=['gcm.test.js','cbc.test.js','palette.test.js'];let failed=0;
for(const f of files){
  console.log('\n=== '+f+' ===');
  const r=spawnSync(process.execPath,[path.join(__dirname,f)],{encoding:'utf8'});
  const lines=(r.stdout||'').trim().split('\n');
  const fails=lines.filter(l=>l.startsWith('FAIL'));
  console.log(fails.join('\n')||'(all checks passed)');
  console.log(lines[lines.length-1]);
  if(r.status!==0){failed++;if(r.stderr)console.error(r.stderr)}
}
console.log(failed?'\nSome tests FAILED':'\nAll test suites passed');
process.exit(failed?1:0);
