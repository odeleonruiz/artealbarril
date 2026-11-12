-- AQUABRI LABORATORIO / 2026-11-12
-- Sesiones verificadas en el servidor; operaciones seguras.
-- SE APLICA SOLO EN STAGING. NO ejecutar en producción con frontend anterior.
-- Estas funciones quedaron instaladas en la base de pruebas.

BEGIN;

CREATE OR REPLACE FUNCTION public.aq_cobrar_credito_sesion_segura_v1(p_nonce text, p_cliente_id bigint, p_monto numeric, p_medio text, p_notas text DEFAULT ''::text, p_credito_id bigint DEFAULT NULL::bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
 v_uid integer; v_role text; v_token text;
BEGIN
 v_uid:=public.aq_sesion_legacy_usuario_actual_v1();
 IF v_uid IS NULL THEN
   RAISE EXCEPTION 'Debes iniciar sesión' USING ERRCODE='42501';
 END IF;
 SELECT rol INTO v_role FROM public.usuarios WHERE id=v_uid;
 IF v_role NOT IN ('jefe','vendedor','vendedor_editor')
    OR NOT aquabri_private.tiene_permiso_usuario(v_uid,'creditos.cobrar') THEN
    RAISE EXCEPTION 'No tienes permiso para cobrar créditos' USING ERRCODE='42501';
 END IF;
 IF p_cliente_id IS NULL OR p_cliente_id<1 OR p_cliente_id>2147483647 THEN
   RAISE EXCEPTION 'Cliente de cobro inválido' USING ERRCODE='22023';
 END IF;
 IF p_credito_id IS NOT NULL AND NOT EXISTS (
   SELECT 1 FROM public.creditos c WHERE c.id=p_credito_id AND c.cliente_id=p_cliente_id
 ) THEN RAISE EXCEPTION 'Crédito de otro cliente' USING ERRCODE='22023'; END IF;

 -- La autorización es para COBRAR cualquier crédito; no concede permiso
 -- para editar libremente clientes o créditos.
 v_token:=(pg_catalog.current_setting('request.headers',true)::jsonb)->>'x-aquabri-session';
 RETURN public.aq_cobrar_credito_seguro(
  v_token,v_uid,p_nonce,p_cliente_id,p_monto,p_medio,p_notas,p_credito_id
 );
END;
$function$
;


CREATE OR REPLACE FUNCTION public.aq_sesion_legacy_puede_ver_cliente_v1(p_cliente integer)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE v_uid integer; v_rol text;
BEGIN
 v_uid:=public.aq_sesion_legacy_usuario_actual_v1();
 IF v_uid IS NULL OR p_cliente IS NULL THEN RETURN false; END IF;
 SELECT rol INTO v_rol FROM public.usuarios WHERE id=v_uid;
 IF v_rol='jefe' THEN RETURN true; END IF;
 RETURN EXISTS(SELECT 1 FROM public.clientes c WHERE c.id=p_cliente AND c.creado_por=v_uid::text)
   OR EXISTS(SELECT 1 FROM public.aq_clientes_atribucion_manual a
             WHERE a.cliente_id=p_cliente AND a.usuario_id=v_uid)
   OR EXISTS(SELECT 1 FROM public.ventas v WHERE v.cliente_id=p_cliente AND v.usuario_id=v_uid);
END;
$function$
;


CREATE OR REPLACE FUNCTION public.aq_sesion_legacy_rol_v1()
 RETURNS text
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
SELECT u.rol FROM public.usuarios u
WHERE u.id=(SELECT public.aq_sesion_legacy_usuario_actual_v1())
LIMIT 1
$function$
;


CREATE OR REPLACE FUNCTION public.aq_vender_sesion_segura_v1(p_nonce text, p_venta jsonb, p_items jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE v_uid integer; v_role text; v_token text; v_cli integer;
 v_venta jsonb; v_res jsonb; v_envases jsonb:=NULL;
 v_llevan integer; v_devuelven integer;
BEGIN
 v_uid:=public.aq_sesion_legacy_usuario_actual_v1();
 IF v_uid IS NULL THEN RAISE EXCEPTION 'Sesión no autorizada' USING ERRCODE='42501'; END IF;
 SELECT rol INTO v_role FROM public.usuarios WHERE id=v_uid;
 IF v_role NOT IN ('jefe','vendedor','vendedor_editor')
   OR NOT aquabri_private.tiene_permiso_usuario(v_uid,'ventas.registrar')
 THEN RAISE EXCEPTION 'No tienes permiso para vender' USING ERRCODE='42501'; END IF;
 IF p_nonce IS NULL OR length(p_nonce) NOT BETWEEN 16 AND 120
  OR p_venta IS NULL OR jsonb_typeof(p_venta)<>'object'
  OR p_items IS NULL OR jsonb_typeof(p_items)<>'array'
 THEN RAISE EXCEPTION 'Datos de la venta inválidos' USING ERRCODE='22023'; END IF;
 IF nullif(p_venta->>'cliente_id','') IS NOT NULL THEN
   v_cli:=(p_venta->>'cliente_id')::integer;
   IF v_cli<1 OR (v_role<>'jefe'
      AND NOT public.aq_sesion_legacy_puede_ver_cliente_v1(v_cli))
   THEN RAISE EXCEPTION 'Cliente no autorizado' USING ERRCODE='42501'; END IF;
 END IF;
 v_llevan:=coalesce((p_venta->>'envases_llevan')::integer,0);
 v_devuelven:=coalesce((p_venta->>'envases_devuelven')::integer,0);
 IF v_llevan NOT BETWEEN 0 AND 100000 OR v_devuelven NOT BETWEEN 0 AND 100000
 THEN RAISE EXCEPTION 'Cantidad de envases inválida' USING ERRCODE='22023'; END IF;
 IF (v_llevan>0 OR v_devuelven>0) AND v_cli IS NULL
 THEN RAISE EXCEPTION 'Selecciona un cliente para registrar envases' USING ERRCODE='22023'; END IF;
 v_token:=(pg_catalog.current_setting('request.headers',true)::jsonb)->>'x-aquabri-session';
 v_venta:=jsonb_set(p_venta,'{usuario_id}',to_jsonb(v_uid),true);
 
 IF v_venta->>'estado'='Pendiente' THEN
   IF v_llevan>0 OR v_devuelven>0 THEN
     RAISE EXCEPTION 'Los envases se registran cuando se entrega el pedido' USING ERRCODE='22023';
   END IF;
   v_res:=public.aq_registrar_venta_completa(v_token,v_uid,p_nonce,v_venta,p_items);
   RETURN v_res||jsonb_build_object('integral',true,'pendiente',true,'envases',NULL);
 END IF;
 v_res:=public.aq_registrar_venta_integral_v2(v_token,v_uid,p_nonce,v_venta,p_items);
 IF v_llevan>0 OR v_devuelven>0 THEN
   v_envases:=public.aq_registrar_envases_venta(
      v_token,v_uid,(v_res->>'id')::bigint,v_llevan,v_devuelven);
 END IF;
 RETURN v_res||jsonb_build_object('envases',v_envases);
END;
$function$
;

REVOKE ALL ON FUNCTION public.aq_sesion_legacy_rol_v1() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_sesion_legacy_rol_v1() TO anon,authenticated;
REVOKE ALL ON FUNCTION public.aq_sesion_legacy_puede_ver_cliente_v1(integer) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_sesion_legacy_puede_ver_cliente_v1(integer) TO anon,authenticated;
REVOKE ALL ON FUNCTION public.aq_vender_sesion_segura_v1(text,jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_vender_sesion_segura_v1(text,jsonb,jsonb) TO anon,authenticated;
REVOKE ALL ON FUNCTION public.aq_cobrar_credito_sesion_segura_v1(text,bigint,numeric,text,text,bigint) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_cobrar_credito_sesion_segura_v1(text,bigint,numeric,text,text,bigint) TO anon,authenticated;

COMMIT;
