-- AQUABRI / laboratorio artealbarril / PRUEBAS DE AUTORIZACIÓN
-- Fecha: 2026-11-09
-- Únicamente para aquabri-staging. NO ejecutar en producción.
-- Requiere acceso administrativo al SQL editor y usuarios ficticios enlazados:
-- un jefe y un vendedor en public.usuarios con auth_uid.
-- No revela tokens ni contraseñas; simula el claim JWT dentro de transacciones
-- y fija el rol de base de datos como 'authenticated'.
-- Las transacciones terminan en ROLLBACK. No agrega operaciones.

-- A. Vendedor: no puede administrar ni pagar proveedores; sí puede
-- identificar su perfil y llegar a la validación de ventas/cobros.
BEGIN;
DO $setup$
BEGIN
  PERFORM set_config(
    'request.jwt.claim.sub',
    (SELECT auth_uid::text FROM public.usuarios
     WHERE rol='vendedor' AND auth_uid IS NOT NULL ORDER BY id LIMIT 1),
    true
  );
END $setup$;
SET LOCAL ROLE authenticated;
DO $qa$
DECLARE c record; v_result jsonb; n integer:=0; m text;
BEGIN
  FOR c IN
    SELECT * FROM (VALUES
    ('abrir_caja_global', $probe$select public.aq_abrir_caja_auth_v2('QA-TEST',current_date,1.00,null::integer,'QA')$probe$, 'reservada al jefe'),
    ('aprobar_vendedor', $probe$select public.aq_aprobar_vendedor_qa_v1(1::bigint)$probe$, 'Solo el jefe'),
    ('auditar_fifo', $probe$select public.aq_auditoria_fifo_auth_v1()$probe$, 'Solo jefe'),
    ('abrir_caja_qa', $probe$select public.aq_caja_abrir_qa_jefe_v1('QA-TEST',current_date,1.00,'QA')$probe$, 'Solo jefe'),
    ('cerrar_caja_qa', $probe$select public.aq_caja_cerrar_qa_jefe_v1('QA-TEST',current_date,1::integer,1.00,1.00,0::integer,false,false,'QA')$probe$, 'Solo jefe'),
    ('resumen_caja', $probe$select public.aq_caja_resumen_qa_auth_v1(current_date)$probe$, 'Solo el jefe'),
    ('cerrar_caja_global', $probe$select public.aq_cerrar_caja_auth_v2('QA-TEST',current_date,1::integer,1.00,1.00,0::integer,false,false,'QA')$probe$, 'reservado al jefe'),
    ('registrar_compras', $probe$select public.aq_comprar_auth_v2('QA-TEST','{}'::jsonb,'[]'::jsonb)$probe$, 'Rol sin permiso'),
    ('consultar_proveedores', $probe$select public.aq_deudas_proveedores_auth_v1()$probe$, 'Solo el jefe'),
    ('pagar_proveedor', $probe$select public.aq_pagar_proveedor_auth_v1('QA-TEST','QA',null::bigint,1.00,current_date,'QA','caja')$probe$, 'Solo el jefe'),
    ('solicitudes_pendientes', $probe$select public.aq_solicitudes_vendedor_pendientes_qa_v1()$probe$, 'Solo el jefe'),
    ('pedir_otro_acceso', $probe$select public.aq_solicitar_vendedor_qa_v1()$probe$, 'ya está vinculada'),
    ('vender_validacion', $probe$select public.aq_vender_auth_v2('QA-TEST','[]'::jsonb,'[]'::jsonb)$probe$, 'Datos de venta invalidos'),
    ('cobrar_validacion', $probe$select public.aq_cobrar_auth_v2('QA-TEST',0::bigint,1.00,'efectivo','',null::bigint)$probe$, 'Cliente de cobro inválido'),
    ('ver_perfil', $probe$select public.aq_mi_perfil_seguro()$probe$, 'SUCCESS')
    ) AS checks(test_name, command, expect)
  LOOP
    BEGIN
      v_result:=NULL;
      EXECUTE c.command INTO v_result;
      IF c.expect='SUCCESS' THEN
        IF v_result->>'rol' IS DISTINCT FROM 'vendedor' THEN
          RAISE EXCEPTION 'QA_PERFIL_INCORRECTO';
        END IF;
      ELSE
        RAISE EXCEPTION 'QA_ACCESO_INDEBIDO';
      END IF;
    EXCEPTION WHEN OTHERS THEN
      m:=SQLERRM;
      IF c.expect='SUCCESS' OR position(c.expect IN m)=0 THEN
        RAISE EXCEPTION 'Prueba fallida %: %; se esperaba %', c.test_name, m, c.expect;
      END IF;
    END;
    n:=n+1;
  END LOOP;
  IF n<>15 THEN RAISE EXCEPTION 'Número de comprobaciones inesperado'; END IF;
END $qa$;
ROLLBACK;

-- B. Identidad JWT no enlazada: debe ser rechazada por el servidor.
BEGIN;
DO $setup$
BEGIN
  PERFORM set_config('request.jwt.claim.sub',gen_random_uuid()::text,true);
END $setup$;
SET LOCAL ROLE authenticated;
DO $qa$
DECLARE c record; v_result jsonb; n integer:=0; m text;
BEGIN
  FOR c IN
    SELECT * FROM (VALUES
    ('perfil', $probe$select public.aq_mi_perfil_seguro()$probe$, 'Usuario no autorizado'),
    ('venta', $probe$select public.aq_vender_auth_v2('QA-AUD-TEST','{}'::jsonb,'[]'::jsonb)$probe$, 'La identidad no existe'),
    ('cobro', $probe$select public.aq_cobrar_auth_v2('QA-AUD-TEST',1::bigint,1.00,'efectivo','',null::bigint)$probe$, 'La identidad no existe'),
    ('aprobar', $probe$select public.aq_aprobar_vendedor_qa_v1(1::bigint)$probe$, 'Solo el jefe')
    ) AS checks(test_name, command, expect)
  LOOP
    BEGIN
      v_result:=NULL;
      EXECUTE c.command INTO v_result;
      IF c.expect='SUCCESS' THEN
        IF v_result->>'rol' IS DISTINCT FROM 'vendedor' THEN
          RAISE EXCEPTION 'QA_PERFIL_INCORRECTO';
        END IF;
      ELSE
        RAISE EXCEPTION 'QA_ACCESO_INDEBIDO';
      END IF;
    EXCEPTION WHEN OTHERS THEN
      m:=SQLERRM;
      IF c.expect='SUCCESS' OR position(c.expect IN m)=0 THEN
        RAISE EXCEPTION 'Prueba fallida %: %; se esperaba %', c.test_name, m, c.expect;
      END IF;
    END;
    n:=n+1;
  END LOOP;
  IF n<>4 THEN RAISE EXCEPTION 'Número de comprobaciones inesperado'; END IF;
END $qa$;
ROLLBACK;

-- C. Jefe: las cuatro consultas protegidas continúan funcionando.
BEGIN;
DO $setup$
BEGIN
  PERFORM set_config(
    'request.jwt.claim.sub',
    (SELECT auth_uid::text FROM public.usuarios
     WHERE rol='jefe' AND auth_uid IS NOT NULL ORDER BY id LIMIT 1),
    true
  );
END $setup$;
SET LOCAL ROLE authenticated;
DO $qa$
BEGIN
 IF (SELECT public.aq_mi_perfil_seguro()->>'rol') IS DISTINCT FROM 'jefe'
 THEN RAISE EXCEPTION 'Perfil de jefe incorrecto'; END IF;
 IF jsonb_typeof(public.aq_auditoria_fifo_auth_v1()) <> 'object'
 THEN RAISE EXCEPTION 'Auditoría FIFO no responde al jefe'; END IF;
 IF jsonb_typeof(public.aq_deudas_proveedores_auth_v1()) <> 'array'
 THEN RAISE EXCEPTION 'Deudas proveedores no responde al jefe'; END IF;
 IF jsonb_typeof(public.aq_caja_resumen_qa_auth_v1(current_date)) <> 'object'
 THEN RAISE EXCEPTION 'Caja no responde al jefe'; END IF;
 IF jsonb_typeof(public.aq_solicitudes_vendedor_pendientes_qa_v1()) <> 'array'
 THEN RAISE EXCEPTION 'Solicitudes no responden al jefe'; END IF;
END $qa$;
ROLLBACK;

-- Resultado al guardar: 15 verificaciones vendedor + 4 identidad no vinculada
-- + 4 consultas administrativas de jefe PASARON en 2026-11-09.
-- Estas son pruebas de acceso, no pruebas de negocio extremo a extremo.
