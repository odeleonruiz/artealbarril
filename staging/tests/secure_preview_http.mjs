import fs from 'node:fs';
import assert from 'node:assert/strict';

const html=fs.readFileSync('staging/secure-preview/index.html','utf8');
const project='xzbawbkstaqvkwtqlqai';
const key=html.match(/const SKEY='(sb_publishable_[^']+)'/);
assert(key,'La vista previa no tiene la llave pública de Staging');
assert(html.includes("const SURL='https://"+project+".supabase.co'"),'Origen de Supabase incorrecto');
assert(!html.includes('odwccqqvxpsggggehjtt'),'Referencia al proyecto oficial en Staging');
assert(html.includes('aq_login_usuario_seguro_v1'),'No se encontró inicio de sesión seguro');
assert(!html.includes("sb.from('usuarios')"),'Acceso directo a usuarios sin proteger');
assert(!html.includes("sb.from('sesiones')"),'Creación directa de sesiones');
const base='https://'+project+'.supabase.co/rest/v1';
const headers={
  apikey:key[1],
  authorization:'Bearer '+key[1],
  accept:'application/json'
};
async function readEmpty(tabla) {
  const r=await fetch(base+'/'+tabla+'?select=id&limit=1',{headers});
  const body=await r.text();
  assert.equal(r.status,200,tabla+' no permite leer bajo RLS: '+r.status+' '+body.slice(0,300));
  assert.deepEqual(JSON.parse(body),[],tabla+' revela datos sin sesión');
  console.log('BLOQUEADO SIN SESIÓN',tabla);
}
for(const tabla of ['clientes','creditos','ventas','venta_items','caja']){
 await readEmpty(tabla);
}
const request=await fetch(base+'/rpc/aq_login_usuario_seguro_v1',{
  method:'POST',
  headers:{...headers,'content-type':'application/json'},
  body:JSON.stringify({p_usuario:'__cuenta_inexistente_qa_20261112',p_password:'invalid_qa'})
});
const body=await request.text();
assert.equal(request.status,200,'RPC de login no responde: '+request.status+' '+body.slice(0,300));
const response=JSON.parse(body);
assert.equal(response.ok,false,'Inicio de sesión aceptó credenciales inexistentes');
assert(!Object.hasOwn(response,'token'),'Inicio de sesión devolvió token sin verificar identidad');
console.log('RECHAZO DE LOGIN INCORRECTO, SIN FILTRACIÓN');
console.log('VALIDACIÓN PRELIMINAR STAGING OK; no reemplaza pruebas con sesión real');
