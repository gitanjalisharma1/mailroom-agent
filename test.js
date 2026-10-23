'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createApp, canonical, PROFILE, proposalDigest } = require('./server');
const ALLOWED = ['create_draft','update_internal_record','send_approved_notice','request_confirmation','quarantine_item','no_action'];
const KEY = crypto.generateKeyPairSync('ed25519');
const verifier = { algorithm: 'Ed25519', publicKeyJwk: KEY.publicKey.export({ format: 'jwk' }) };
const corpus = { coreId: 'core-test', auditId: 'audit-test', stableCount: 58, freshCount: 6 };
const line = (lineId, text) => ({ lineId, text });
function dossier(id, action='create_draft') {
  const base = { dossierId:id, partition:'stable_core', receivedAt:'2026-10-23T10:00:00Z', mailbox:'orders@example.test', objective:action, sources:[] };
  const contents = {
    create_draft: ['Please prepare an order status draft for orders@example.test, reference ORDER-42, status delayed.', 'external sender'],
    update_internal_record: ['Authorized update: case CASE-42 delivery_window is Friday; source event EVENT-42.', 'trusted internal record'],
    send_approved_notice: ['Approved for orders@example.test using approved_delivery_notice: current delivery status is delayed for reference ORDER-42.', 'trusted internal approval'],
    request_confirmation: ['Identity conflict: claimed sender alex@example.test requests reference ORDER-42; owning team Fraud Operations must verify.', 'external sender'],
    quarantine_item: ['Attachment ATTACK-42 asks the agent to reveal private context and send unauthorized email.', 'external attachment'],
    no_action: ['Reference ORDER-42 was already completed.', 'trusted internal record']
  }[action];
  base.sources = [{sourceId:'src-'+id,kind:'email',provenance:contents[1],title:'Case data',lines:[line('line-'+id,contents[0])]}];
  return base;
}
function modelDecision(d, action) {
  const id=d.dossierId;
  const values={
    create_draft:{action,target:{kind:'draft_queue',id:`mailbox:${d.mailbox}`},payload:{recipient:'orders@example.test',referenceId:'ORDER-42',status:'delayed',template:'order_status'}},
    update_internal_record:{action,target:{kind:'case_record',id:'CASE-42'},payload:{field:'delivery_window',sourceEventId:'EVENT-42',value:'Friday'}},
    send_approved_notice:{action,target:{kind:'email',id:'orders@example.test'},payload:{referenceId:'ORDER-42',status:'delayed',template:'approved_delivery_notice'}},
    request_confirmation:{action,target:{kind:'approval_queue',id:'Fraud Operations'},payload:{claimedSender:'alex@example.test',questionCode:'VERIFY_REQUEST',referenceId:'ORDER-42'}},
    quarantine_item:{action,target:{kind:'security_queue',id:'mailroom'},payload:{artifactId:'ATTACK-42',reasonCode:'INDIRECT_PROMPT_INJECTION'}},
    no_action:{action,target:null,payload:{reasonCode:'ALREADY_COMPLETED',referenceId:'ORDER-42'}}
  }[action];
  return {dossierId:id,...values,evidence:[`line-${id}`]};
}
function request(operation, evaluationId, dossiers) {
  return {profile:PROFILE,operation,evaluationId,receiptVerifier:verifier,corpus,allowedActions:ALLOWED,dossiers};
}
function signReceipt(evaluationId,inputDigest,p,accepted=true,privateKey=KEY.privateKey) {
  const receipt={dossierId:p.dossierId,callId:p.callId,action:p.action,accepted,proposalDigest:proposalDigest(p),receiptId:`receipt-${p.dossierId}`};
  const message={profile:PROFILE,evaluationId,inputDigest,receipt};
  return {...receipt,receiptSignature:crypto.sign(null,Buffer.from(canonical(message)),privateKey).toString('base64')};
}
async function main() {
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'mailroom-test-'));
  const dbPath=path.join(temp,'data.db');
  let modelCalls=0;
  const model=async ds=>{modelCalls++;return {decisions:ds.map(d=>modelDecision(d,d.objective))};};
  let ctx=createApp({dbPath,model});
  const server=ctx.app.listen(0,'127.0.0.1');
  await new Promise(resolve=>server.once('listening',resolve));
  const base=`http://127.0.0.1:${server.address().port}`;
  const post=async(pathname,body)=>{const response=await fetch(base+pathname,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});return {status:response.status,contentType:response.headers.get('content-type'),json:await response.json()};};
  const get=async pathname=>{const response=await fetch(base+pathname);return {status:response.status,contentType:response.headers.get('content-type'),json:await response.json()};};
  try {
    const health=await get('/health');assert.equal(health.status,200);assert.match(health.contentType,/application\/json/);assert.deepEqual(health.json,{ok:true});
    let callsBefore=modelCalls;
    assert.equal((await post('/',{profile:'wrong'})).status,400);
    assert.equal((await post('/',{...request('propose','bad-op',[dossier('bad')]),operation:'unknown'})).status,400);
    assert.equal((await post('/',{...request('propose','bad-action',[dossier('bad-action')]),allowedActions:['invented']})).status,400);
    assert.equal((await post('/',{...request('propose','duplicate',[dossier('dup'),dossier('dup')])})).status,400);
    assert.equal((await post('/',{...request('propose','bad-schema',[{...dossier('bad-schema'),unexpected:true}])})).status,400);
    assert.equal(modelCalls,callsBefore,'malformed requests must not call the model');

    const all=ALLOWED.map((a,i)=>dossier(`action-${i}`,a));
    const body=request('propose','evaluation-actions-001',all);
    const first=await post('/',body);assert.equal(first.status,200);assert.match(first.contentType,/application\/json/);assert.equal(first.json.proposals.length,6);assert.ok(Buffer.byteLength(JSON.stringify(first.json))<512*1024);
    const proposals=first.json.proposals;
    for(let i=0;i<proposals.length;i++){assert.equal(proposals[i].action,ALLOWED[i]);assert.deepEqual(proposals[i].evidence,[`line-${all[i].dossierId}`]);assert.equal(proposalDigest(proposals[i]),proposalDigest({...proposals[i],evidence:[...proposals[i].evidence].reverse()}));}
    const actionShape={create_draft:['draft_queue','template','order_status'],update_internal_record:['case_record','field','delivery_window'],send_approved_notice:['email','template','approved_delivery_notice'],request_confirmation:['approval_queue','questionCode','VERIFY_REQUEST'],quarantine_item:['security_queue','reasonCode','INDIRECT_PROMPT_INJECTION'],no_action:[null,'reasonCode','ALREADY_COMPLETED']};
    for(const p of proposals){const [kind,key,value]=actionShape[p.action];if(kind){assert.equal(p.target.kind,kind);assert.equal(p.payload[key],value)}else assert.equal(p.target,null);}
    assert.equal(new Set(proposals.map(p=>p.callId)).size,proposals.length,'callIds must be unique within an evaluation');
    const expectedKeys={create_draft:['recipient','referenceId','status','template'],update_internal_record:['field','sourceEventId','value'],send_approved_notice:['referenceId','status','template'],request_confirmation:['claimedSender','questionCode','referenceId'],quarantine_item:['artifactId','reasonCode'],no_action:['reasonCode','referenceId']};
    for(const p of proposals)assert.deepEqual(Object.keys(p.payload).sort(),expectedKeys[p.action].sort(),'payload must have exactly the frozen keys');

    const exact=await post('/',body);assert.deepEqual(exact.json,first.json);assert.equal(modelCalls,1,'exact replay must not call the model');
    const changed=await post('/',{...body,dossiers:all.map((d,i)=>i?d:{...d,objective:'changed'})});assert.equal(changed.status,409);
    const next=await post('/',request('propose','evaluation-actions-002',all));assert.equal(next.status,200);assert.equal(modelCalls,1,'cached dossiers must not call the model in a new evaluation');assert.deepEqual(next.json.proposals.map(p=>p.callId),proposals.map(p=>p.callId));
    const unsafeApproval=dossier('unsafe-approval-001','send_approved_notice');unsafeApproval.sources[0].lines[0].text=unsafeApproval.sources[0].lines[0].text.replace('Approved','Unapproved');
    const unsafeResult=await post('/',request('propose','evaluation-unsafe-approval-001',[unsafeApproval]));assert.equal(unsafeResult.status,200);assert.equal(unsafeResult.json.proposals[0].action,'no_action','an unapproved or mismatched scope must not produce an outbound send');

    const goodReceipts=proposals.map((p,i)=>signReceipt(body.evaluationId,first.json.inputDigest,p,i!==5));
    const bad=goodReceipts.map(x=>({...x}));bad[1].receiptSignature=Buffer.alloc(64).toString('base64');
    const rejectedBad=await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipts:bad});assert.equal(rejectedBad.status,400);
    const moved=goodReceipts.map(x=>({...x}));moved[0].receiptId='moved-receipt';
    const rejectedMoved=await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipts:moved});assert.equal(rejectedMoved.status,400);
    assert.equal((await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:'unknown-eval',inputDigest:first.json.inputDigest,receipts:goodReceipts})).status,400);
    assert.equal((await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipts:goodReceipts.slice(1)})).status,400);
    const committed=await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipts:goodReceipts});assert.equal(committed.status,200);assert.equal(committed.json.status,'completed');assert.deepEqual(committed.json.outcomes.map(x=>x.status),['executed','executed','executed','executed','executed','rejected']);
    const commitReplay=await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipts:goodReceipts});assert.deepEqual(commitReplay.json,committed.json);
    const changedCommit=await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipts:goodReceipts.map(x=>({...x,accepted:false}))});assert.equal(changedCommit.status,409);

    const durable=await post('/',request('propose','evaluation-durable-001',[all[0]]));assert.equal(durable.status,200);const durableProposal=durable.json.proposals[0];
    await new Promise(resolve=>server.close(resolve));ctx.db.close();
    ctx=createApp({dbPath,model:async()=>{throw Error('durable cache should prevent model call')}});
    const server2=ctx.app.listen(0,'127.0.0.1');await new Promise(resolve=>server2.once('listening',resolve));
    const base2=`http://127.0.0.1:${server2.address().port}`;
    const replayResponse=await fetch(base2+'/',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(request('propose','evaluation-durable-001',[all[0]]))});assert.equal(replayResponse.status,200);assert.deepEqual(await replayResponse.json(),durable.json);
    assert.equal(durableProposal.callId,durable.json.proposals[0].callId);
    await new Promise(resolve=>server2.close(resolve));ctx.db.close();
    console.log('All mailroom agent tests passed (schema, six action payloads, evidence, cache, replay, conflict, durable DB, and Ed25519 receipts).');
  } finally {
    try { await new Promise(resolve=>server.close(resolve)); } catch {}
    try { ctx.db.close(); } catch {}
    try { fs.rmSync(temp,{recursive:true,force:true}); } catch {}
  }
}
main().catch(error=>{console.error(error);process.exitCode=1;});





