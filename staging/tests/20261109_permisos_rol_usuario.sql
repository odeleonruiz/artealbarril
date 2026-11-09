-- AQUABRI Staging. Prueba reversible de permisos predeterminados y excepciones.
-- Ejecución exclusivamente contra aquabri-staging.
-- Nunca modifica de forma permanente roles, ventas, créditos, caja ni usuarios.
BEGIN;
SELECT set_config('qa.boss',(SELECT id::text FROM public.usuarios WHERE rol='jefe' LIMIT 1),true);
SELECT set_config('qa.vendor',(SELECT id::text FROM public.usuarios WHERE rol='vendedor' LIMIT 1),true);
SELECT set_config('qa.boss_auth',(SELECT auth_uid::text FROM public.usuarios WHERE rol='jefe' LIMIT 1),true);
SELECT set_config('qa.vendor_auth',(SELECT auth_uid::text FROM public.usuarios WHERE rol='vendedor' LIMIT 1),true);
SELECT set_config('request.jwt.claim.sub',current_setting('qa.boss_auth'),true);
SET LOCAL ROLE authenticated;
DO $qa$
DECLARE v_id int:=current_setting('qa.vendor')::int; v_j jsonb; rechaza boolean;
BEGIN
  -- Jefe ve la pantalla de permisos.
  v_j:=public.aq_permisos_administrar_listar_v1();
  IF jsonb_array_length(v_j->'usuarios')<1 THEN RAISE EXCEPTION 'Sin empleados QA'; END IF;
  -- Vendedor viene con ventas y cobros, pero no pagar proveedores.
  PERFORM set_config('request.jwt.claim.sub',current_setting('qa.vendor_auth'),true);
  v_j:=public.aq_mis_permisos_auth_v1();
  IF NOT ((v_j->'permisos') ? 'ventas.registrar')
     OR NOT ((v_j->'permisos') ? 'creditos.cobrar')
     OR ((v_j->'permisos') ? 'proveedores.pagar') THEN
    RAISE EXCEPTION 'Permisos iniciales de vendedor incorrectos';
  END IF;
  rechaza:=false;
  BEGIN PERFORM public.aq_permisos_administrar_listar_v1();
  EXCEPTION WHEN SQLSTATE '42501' THEN rechaza:=true; END;
  IF NOT rechaza THEN RAISE EXCEPTION 'Vendedor administra permisos'; END IF;

  -- El jefe concede y revoca permisos individuales.
  PERFORM set_config('request.jwt.claim.sub',current_setting('qa.boss_auth'),true);
  PERFORM public.aq_asignar_permiso_auth_v1(v_id,'proveedores.ver',true,'QA');
  PERFORM public.aq_asignar_permiso_auth_v1(v_id,'ventas.registrar',false,'QA');
  PERFORM public.aq_asignar_permiso_auth_v1(v_id,'creditos.cobrar',false,'QA');

  -- El vendedor puede consultar proveedores, pero ya no vender ni cobrar.
  PERFORM set_config('request.jwt.claim.sub',current_setting('qa.vendor_auth'),true);
  v_j:=public.aq_deudas_proveedores_auth_v1();
  IF jsonb_typeof(v_j)<>'array' THEN RAISE EXCEPTION 'Permiso extra no funciona'; END IF;
  rechaza:=false;
  BEGIN PERFORM public.aq_vender_auth_v2('QA-TEST','[]'::jsonb,'[]'::jsonb);
  EXCEPTION WHEN OTHERS THEN rechaza:=position('Rol sin permiso para vender' IN sqlerrm)>0; END;
  IF NOT rechaza THEN RAISE EXCEPTION 'Vendedor puede vender pese a revocación'; END IF;
  rechaza:=false;
  BEGIN PERFORM public.aq_cobrar_auth_v2('QA-TEST',1,1,'efectivo','QA',1);
  EXCEPTION WHEN OTHERS THEN rechaza:=position('Rol sin permiso para cobrar' IN sqlerrm)>0; END;
  IF NOT rechaza THEN RAISE EXCEPTION 'Vendedor puede cobrar pese a revocación'; END IF;

  -- Jefe vuelve al predeterminado del rol.
  PERFORM set_config('request.jwt.claim.sub',current_setting('qa.boss_auth'),true);
  v_j:=public.aq_asignar_permiso_auth_v1(v_id,'ventas.registrar',null,'QA restaurar');
  IF (v_j->>'efectivo')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'No restauró ventas'; END IF;
  v_j:=public.aq_asignar_permiso_auth_v1(v_id,'creditos.cobrar',null,'QA restaurar');
  IF (v_j->>'efectivo')::boolean IS NOT TRUE THEN RAISE EXCEPTION 'No restauró cobros'; END IF;

  -- Nadie puede delegar la administración de permisos ni modificar al jefe.
  rechaza:=false;
  BEGIN PERFORM public.aq_asignar_permiso_auth_v1(v_id,'seguridad.permisos',true,'QA');
  EXCEPTION WHEN SQLSTATE '42501' THEN rechaza:=true; END;
  IF NOT rechaza THEN RAISE EXCEPTION 'Escalamiento de privilegios'; END IF;
  rechaza:=false;
  BEGIN PERFORM public.aq_asignar_permiso_auth_v1(
      current_setting('qa.boss')::int,'ventas',false,'QA');
  EXCEPTION WHEN SQLSTATE '42501' THEN rechaza:=true; END;
  IF NOT rechaza THEN RAISE EXCEPTION 'Permisos del jefe modificables'; END IF;
END
$qa$;
ROLLBACK;
SELECT
  (SELECT count(*) FROM public.aq_usuarios_permisos) AS excepciones_restantes,
  (SELECT count(*) FROM public.aq_permisos_auditoria) AS auditorias_persistentes,
  (SELECT count(*) FROM public.ventas) AS ventas,
  (SELECT count(*) FROM public.caja) AS caja;