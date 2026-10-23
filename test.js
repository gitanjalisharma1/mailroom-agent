'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createApp,canonical,PROFILE,proposalDigest}=require('./server');
async function main(){
 const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519'),jwk=publicKey.export({format:'jwk'});
 const dossier={dossierId:'dossier-test-0001',partition:'stable_core',receivedAt:'2026-10-23T10:00:00Z',mailbox:'orders@example.test',objective:'Prepare a draft response',sources:[{sourceId:'src-0001',kind:'email',provenance:'external sender',title:'Order question',lines:[{lineId:'line-0001',text:'Please send an update about reference ORDER-42 to orders@example.test; current status requested.'}]}]};
 const body={profile:PROFILE,operation:'propose',evaluationId:'evaluation-test-0001',receiptVerifier:{algorithm:'Ed25519',publicKeyJwk:jwk},corpus:{coreId:'core-1',auditId:'audit-1',stableCount:58,freshCount:6},allowedActions:['create_draft','update_internal_record','send_approved_notice','request_confirmation','quarantine_item','no_action'],dossiers:[dossier]};
 const {app,db}=createApp({dbPath:':memory:',model:async ds=>({decisions:ds.map(d=>({dossierId:d.dossierId,action:'create_draft',target:{kind:'draft_queue',id:`mailbox:${d.mailbox}`},payload:{recipient:'orders@example.test',referenceId:'ORDER-42',status:'requested',template:'order_status'},evidence:['line-0001']}))})});
 const srv=app.listen(0,'127.0.0.1');await new Promise(r=>srv.once('listening',r));let base=`http://127.0.0.1:${srv.address().port}`;
 const post=async(path,b)=>{let x=await fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});return{status:x.status,json:await x.json()}};
 try{
  assert.equal((await post('/',{...body,profile:'bad'})).status,400);
  assert.equal((await post('/',{...body,evaluationId:'evaluation-duplicate-0001',dossiers:[dossier,dossier]})).status,400);
  let first=await post('/propose',body);assert.equal(first.status,200);assert.equal(first.json.proposals[0].action,'create_draft');let replay=await post('/',body);assert.deepEqual(replay.json,first.json);
  assert.equal((await post('/',{...body,dossiers:[{...dossier,objective:'changed'}]})).status,409);
  let p=first.json.proposals[0],receipt={dossierId:p.dossierId,callId:p.callId,action:p.action,accepted:true,proposalDigest:proposalDigest(p),receiptId:'receipt-test-0001'};
  let signed={profile:PROFILE,evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipt};let sig=crypto.sign(null,Buffer.from(canonical(signed)),privateKey).toString('base64');
  let commit=await post('/commit',{profile:PROFILE,operation:'commit',evaluationId:body.evaluationId,inputDigest:first.json.inputDigest,receipts:[{...receipt,receiptSignature:sig}]});assert.equal(commit.status,200);assert.equal(commit.json.status,'completed');
  let body2={...body,evaluationId:'evaluation-bad-signature-0001'},second=await post('/',body2),p2=second.json.proposals[0],r2={dossierId:p2.dossierId,callId:p2.callId,action:p2.action,accepted:true,proposalDigest:proposalDigest(p2),receiptId:'receipt-test-0002',receiptSignature:Buffer.alloc(64).toString('base64')};
  assert.equal((await post('/',{profile:PROFILE,operation:'commit',evaluationId:body2.evaluationId,inputDigest:second.json.inputDigest,receipts:[r2]})).status,400);
  console.log('All mailroom agent tests passed.');
 }finally{await new Promise(r=>srv.close(r));db.close()}
}
main().catch(e=>{console.error(e);process.exitCode=1});


