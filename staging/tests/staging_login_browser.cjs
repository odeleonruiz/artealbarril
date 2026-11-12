const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true});
  try{
    const page=await browser.newPage({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
    const url='https://odeleonruiz.github.io/artealbarril/staging/secure-preview/';
    const r=await page.goto(url,{waitUntil:'domcontentloaded',timeout:30000});
    assert(r&&r.status()===200,'No cargó la vista previa: '+r?.status());
    assert((await page.title()).includes('QA'),'La pantalla no indica entorno de pruebas');
    assert((await page.locator('#aq-qa-banner').count())===1,'Falta advertencia de laboratorio');
    await page.waitForFunction(()=>{
      const el=document.querySelector('#login-screen');
      return el&&el.classList.contains('show');
    },null,{timeout:35000});
    const login=page.locator('#login-screen');
    assert(await login.isVisible(),'Formulario de acceso no visible');
    assert(!(await page.locator('#app').isVisible()),'La aplicación se mostró sin iniciar sesión');
    console.log('PASS: vista previa móvil muestra login y protege el panel.');
    await page.screenshot({path:'staging-login-smoke.png',fullPage:false});
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
