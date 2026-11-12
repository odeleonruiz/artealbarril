-- AQUABRI LABORATORIO: 2026-11-12
-- Definiciones verificadas en la base de pruebas.
-- REQUIERE primero las dependencias del laboratorio: tablas de operaciones,
-- autenticación por x-aquabri-session, sesion/rol y motores seguros existentes.
-- No aplicar en producción antes de migrar el frontend, verificar respaldos
-- restaurables y ejecutar pruebas con usuarios reales.
BEGIN;

CREATE OR REPLACE FUNCTION public.aq_abrir_caja_sesion_v1(p_nonce text, p_fecha date, p_monto numeric, p_usuario_caja integer DEFAULT NULL::integer, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
 SELECT u.id AS usuario_id,u.rol AS rol_usuario,
  (pg_catalog.current_setting('request.headers',true)::jsonb)->>'x-aquabri-session' AS sesion_token
  INTO STRICT ctx FROM public.usuarios u
  WHERE u.id=public.aq_sesion_legacy_usuario_actual_v1();
 IF ctx.rol_usuario <> 'jefe'
    OR NOT aquabri_private.tiene_permiso_usuario(ctx.usuario_id,'caja.abrir')
 THEN
   RAISE EXCEPTION 'Apertura de Caja global reservada al jefe' USING ERRCODE='42501';
 END IF;
 RETURN public.aq_caja_abrir_seguro(
   ctx.sesion_token,ctx.usuario_id,p_nonce,p_fecha,p_monto,
   coalesce(p_usuario_caja,ctx.usuario_id::integer),p_notas
 );
END;
$function$
;
REVOKE ALL ON FUNCTION public.aq_abrir_caja_sesion_v1(p_nonce text, p_fecha date, p_monto numeric, p_usuario_caja integer, p_notas text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_abrir_caja_sesion_v1(p_nonce text, p_fecha date, p_monto numeric, p_usuario_caja integer, p_notas text) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_archivar_cliente_sesion_v1(p_cliente_id integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare ctx record; c public.clientes%rowtype; v_hist integer;
begin
 select u.id AS usuario_id,u.rol AS rol_usuario into strict ctx
   from public.usuarios u where u.id=public.aq_sesion_legacy_usuario_actual_v1();
 if ctx.rol_usuario <> 'jefe' then
   raise exception 'Solo el jefe puede archivar clientes' using errcode='42501';
 end if;
 if p_cliente_id is null or p_cliente_id < 1 then
   raise exception 'Cliente invalido' using errcode='22023';
 end if;
 select * into c from public.clientes where id=p_cliente_id for update;
 if not found then raise exception 'Cliente no existe' using errcode='22023'; end if;
 if c.archivado_en is not null then
   return pg_catalog.jsonb_build_object('ok',true,'repetida',true,'id',c.id);
 end if;
 if coalesce(c.envases,0)>0
  or exists(select 1 from public.creditos cr where cr.cliente_id=c.id and coalesce(cr.monto,0)>coalesce(cr.pagado,0))
  or exists(select 1 from public.ventas v where v.cliente_id=c.id and v.estado in ('Pendiente','Preparando','En Camino'))
 then
   raise exception 'Hay envases, creditos o pedidos pendientes para este cliente' using errcode='22023';
 end if;
 insert into public.clientes_eliminados(
 nombre,ruta,telefono,direccion,lat,lng,tiene_exhibidor,datos_completos,
 fecha_eliminacion,eliminado_por,cliente_original_id
 )
 values (c.nombre,c.ruta,c.telefono,c.direccion,c.lat,c.lng,c.tiene_exhibidor,
 pg_catalog.to_jsonb(c),(now() at time zone 'America/Guatemala')::date,
 (select nombre from public.usuarios where id=ctx.usuario_id),c.id)
 returning id into v_hist;
 update public.clientes set archivado_en=now(),archivado_por=ctx.usuario_id where id=c.id;
 return pg_catalog.jsonb_build_object('ok',true,'id',c.id,'historial_id',v_hist);
end;$function$
;
REVOKE ALL ON FUNCTION public.aq_archivar_cliente_sesion_v1(p_cliente_id integer) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_archivar_cliente_sesion_v1(p_cliente_id integer) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_cerrar_caja_sesion_v1(p_nonce text, p_fecha date, p_apertura_id integer, p_contado numeric, p_esperado_cliente numeric, p_num_movimientos integer, p_acepta_sin_clasificar boolean DEFAULT false, p_acepta_diferencia boolean DEFAULT false, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
 SELECT u.id AS usuario_id,u.rol AS rol_usuario,
  (pg_catalog.current_setting('request.headers',true)::jsonb)->>'x-aquabri-session' AS sesion_token
  INTO STRICT ctx FROM public.usuarios u
  WHERE u.id=public.aq_sesion_legacy_usuario_actual_v1();
 IF ctx.rol_usuario <> 'jefe'
    OR NOT aquabri_private.tiene_permiso_usuario(ctx.usuario_id,'caja.cerrar')
 THEN
   RAISE EXCEPTION 'Cierre de Caja global reservado al jefe' USING ERRCODE='42501';
 END IF;
 RETURN public.aq_caja_cerrar_seguro(
   ctx.sesion_token,ctx.usuario_id,p_nonce,p_fecha,p_apertura_id,
   p_contado,p_esperado_cliente,p_num_movimientos,
   p_acepta_sin_clasificar,p_acepta_diferencia,p_notas
 );
END;
$function$
;
REVOKE ALL ON FUNCTION public.aq_cerrar_caja_sesion_v1(p_nonce text, p_fecha date, p_apertura_id integer, p_contado numeric, p_esperado_cliente numeric, p_num_movimientos integer, p_acepta_sin_clasificar boolean, p_acepta_diferencia boolean, p_notas text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_cerrar_caja_sesion_v1(p_nonce text, p_fecha date, p_apertura_id integer, p_contado numeric, p_esperado_cliente numeric, p_num_movimientos integer, p_acepta_sin_clasificar boolean, p_acepta_diferencia boolean, p_notas text) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_crear_cliente_captacion_sesion_v1(p_cliente jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
 v_uid integer;v_rol text;v_nombre text;v_lat numeric;v_lng numeric;v_id integer;
BEGIN
 v_uid:=public.aq_sesion_legacy_usuario_actual_v1();
 IF v_uid IS NULL THEN RAISE EXCEPTION 'Sesión inválida' USING ERRCODE='42501'; END IF;
 SELECT rol INTO v_rol FROM public.usuarios WHERE id=v_uid;
 IF v_rol NOT IN ('jefe','vendedor','vendedor_editor') THEN
  RAISE EXCEPTION 'Rol sin permiso para registrar clientes' USING ERRCODE='42501';END IF;
 IF p_cliente IS NULL OR jsonb_typeof(p_cliente)<>'object' THEN
   RAISE EXCEPTION 'Datos de cliente inválidos' USING ERRCODE='22023';END IF;
 v_nombre:=btrim(coalesce(p_cliente->>'nombre',''));
 IF length(v_nombre) NOT BETWEEN 2 AND 180
 OR length(coalesce(p_cliente->>'telefono',''))>60
 OR length(coalesce(p_cliente->>'direccion',''))>450
 OR length(coalesce(p_cliente->>'ruta',''))>150 THEN
   RAISE EXCEPTION 'Datos del cliente fuera de rango' USING ERRCODE='22023';END IF;
 v_lat:=nullif(p_cliente->>'lat','')::numeric;
 v_lng:=nullif(p_cliente->>'lng','')::numeric;
 IF (v_lat IS NULL)<>(v_lng IS NULL)
 OR (v_lat IS NOT NULL AND (v_lat< -90 OR v_lat>90 OR v_lng< -180 OR v_lng>180))
 THEN RAISE EXCEPTION 'Coordenadas inválidas' USING ERRCODE='22023'; END IF;

 INSERT INTO public.clientes(
  nombre,telefono,direccion,ruta,lat,lng,
  tiene_exhibidor,descripcion_exhibidor,exhibidor_capacidad,exhibidor_costo,
  fecha_nacimiento,creado_por
 ) VALUES(
  v_nombre,coalesce(p_cliente->>'telefono',''),coalesce(p_cliente->>'direccion',''),
  coalesce(p_cliente->>'ruta',''),v_lat,v_lng,
  coalesce((p_cliente->>'tiene_exhibidor')::boolean,false),
  coalesce(p_cliente->>'descripcion_exhibidor',''),
  coalesce((p_cliente->>'exhibidor_capacidad')::integer,0),
  coalesce((p_cliente->>'exhibidor_costo')::numeric,0),
  nullif(p_cliente->>'fecha_nacimiento','')::date,v_uid::text
 ) RETURNING id INTO v_id;

 RETURN jsonb_build_object('cliente_id',v_id,'incentivos_creados',0,
  'mensaje','Cliente registrado correctamente');
END;
$function$
;
REVOKE ALL ON FUNCTION public.aq_crear_cliente_captacion_sesion_v1(p_cliente jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_crear_cliente_captacion_sesion_v1(p_cliente jsonb) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_eliminar_gasto_sesion_v1(p_gasto_id integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
  SELECT u.id AS usuario_id,u.rol AS rol_usuario,
     (pg_catalog.current_setting('request.headers',true)::jsonb)->>'x-aquabri-session' AS sesion_token
     INTO STRICT ctx FROM public.usuarios u
     WHERE u.id=public.aq_sesion_legacy_usuario_actual_v1();
  IF NOT aquabri_private.tiene_permiso_usuario(ctx.usuario_id,'gastos') THEN
    RAISE EXCEPTION 'Sin permiso para eliminar gastos' USING ERRCODE='42501';
  END IF;
  RETURN public.aq_eliminar_gasto_seguro(ctx.sesion_token,ctx.usuario_id,p_gasto_id);
END;
$function$
;
REVOKE ALL ON FUNCTION public.aq_eliminar_gasto_sesion_v1(p_gasto_id integer) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_eliminar_gasto_sesion_v1(p_gasto_id integer) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_guardar_cliente_sesion_v1(p_cliente jsonb, p_cliente_id integer DEFAULT NULL::integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
 ctx record;
 v_id integer;
 v_nombre text;
 v_telefono text;
 v_lat numeric;
 v_lng numeric;
 v_cliente public.clientes%ROWTYPE;
BEGIN
 SELECT u.id AS usuario_id,u.rol AS rol_usuario,
     (pg_catalog.current_setting('request.headers',true)::jsonb)->>'x-aquabri-session' AS sesion_token
     INTO STRICT ctx FROM public.usuarios u
     WHERE u.id=public.aq_sesion_legacy_usuario_actual_v1();
 IF NOT aquabri_private.tiene_permiso_usuario(ctx.usuario_id,'clientes') THEN
   RAISE EXCEPTION 'Sin permiso para gestionar clientes' USING ERRCODE='42501';
 END IF;
 IF p_cliente IS NULL OR pg_catalog.jsonb_typeof(p_cliente)<>'object' THEN
   RAISE EXCEPTION 'Datos de cliente inválidos' USING ERRCODE='22023';
 END IF;
 IF p_cliente_id IS NOT NULL AND (p_cliente_id<1 OR p_cliente_id>2147483647) THEN
   RAISE EXCEPTION 'Cliente inválido' USING ERRCODE='22023';
 END IF;
 v_nombre := nullif(pg_catalog.btrim(p_cliente->>'nombre'),'');
 v_telefono:=nullif(pg_catalog.btrim(p_cliente->>'telefono'),'');
 v_lat := nullif(p_cliente->>'lat','')::numeric;
 v_lng := nullif(p_cliente->>'lng','')::numeric;
 IF (v_lat IS NOT NULL AND (v_lat < -90 OR v_lat>90))
   OR (v_lng IS NOT NULL AND (v_lng < -180 OR v_lng>180))
   OR length(coalesce(v_nombre,''))>200 OR length(coalesce(v_telefono,''))>60
   OR length(coalesce(p_cliente->>'ruta',''))>100
   OR length(coalesce(p_cliente->>'direccion',''))>500 THEN
   RAISE EXCEPTION 'Datos de cliente fuera de rango' USING ERRCODE='22023';
 END IF;
 IF p_cliente_id IS NULL THEN
   IF v_nombre IS NULL OR length(v_nombre)<2 THEN
     RAISE EXCEPTION 'Nombre del cliente requerido' USING ERRCODE='22023';
   END IF;
   INSERT INTO public.clientes(nombre,telefono,direccion,ruta,lat,lng,
       tiene_exhibidor,descripcion_exhibidor,exhibidor_capacidad,exhibidor_costo,
       fecha_nacimiento,creado_por)
   VALUES(v_nombre,v_telefono,p_cliente->>'direccion',p_cliente->>'ruta',v_lat,v_lng,
      coalesce((p_cliente->>'tiene_exhibidor')::boolean,false),
      p_cliente->>'descripcion_exhibidor',
      coalesce((p_cliente->>'exhibidor_capacidad')::integer,0),
      coalesce((p_cliente->>'exhibidor_costo')::numeric,0),
      nullif(p_cliente->>'fecha_nacimiento','')::date,
      ctx.usuario_id::text)
   RETURNING id INTO v_id;
 ELSE
   IF ctx.rol_usuario<>'jefe' AND
      NOT public.aq_sesion_legacy_puede_ver_cliente_v1(p_cliente_id) THEN
     RAISE EXCEPTION 'No puedes editar este cliente' USING ERRCODE='42501';
   END IF;
   SELECT * INTO v_cliente FROM public.clientes WHERE id=p_cliente_id FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'Cliente inexistente' USING ERRCODE='22023'; END IF;
   IF p_cliente ? 'nombre' AND (v_nombre IS NULL OR length(v_nombre)<2) THEN
     RAISE EXCEPTION 'Nombre inválido' USING ERRCODE='22023';
   END IF;
   UPDATE public.clientes SET
     nombre=CASE WHEN p_cliente ? 'nombre' THEN v_nombre ELSE nombre END,
     telefono=CASE WHEN p_cliente ? 'telefono' THEN v_telefono ELSE telefono END,
     direccion=CASE WHEN p_cliente ? 'direccion' THEN p_cliente->>'direccion' ELSE direccion END,
     ruta=CASE WHEN p_cliente ? 'ruta' THEN p_cliente->>'ruta' ELSE ruta END,
     lat=CASE WHEN p_cliente ? 'lat' THEN v_lat ELSE lat END,
     lng=CASE WHEN p_cliente ? 'lng' THEN v_lng ELSE lng END,
     tiene_exhibidor=CASE WHEN p_cliente ? 'tiene_exhibidor' THEN (p_cliente->>'tiene_exhibidor')::boolean ELSE tiene_exhibidor END,
     descripcion_exhibidor=CASE WHEN p_cliente ? 'descripcion_exhibidor' THEN p_cliente->>'descripcion_exhibidor' ELSE descripcion_exhibidor END,
     exhibidor_capacidad=CASE WHEN p_cliente ? 'exhibidor_capacidad' THEN (p_cliente->>'exhibidor_capacidad')::integer ELSE exhibidor_capacidad END,
     exhibidor_costo=CASE WHEN p_cliente ? 'exhibidor_costo' THEN (p_cliente->>'exhibidor_costo')::numeric ELSE exhibidor_costo END,
     fecha_nacimiento=CASE WHEN p_cliente ? 'fecha_nacimiento' THEN nullif(p_cliente->>'fecha_nacimiento','')::date ELSE fecha_nacimiento END
   WHERE id=p_cliente_id RETURNING id INTO v_id;
 END IF;
 RETURN pg_catalog.jsonb_build_object('id',v_id,'ok',true);
END;
$function$
;
REVOKE ALL ON FUNCTION public.aq_guardar_cliente_sesion_v1(p_cliente jsonb, p_cliente_id integer) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_guardar_cliente_sesion_v1(p_cliente jsonb, p_cliente_id integer) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_registrar_gasto_sesion_v1(p_nonce text, p_gasto jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
  SELECT u.id AS usuario_id,u.rol AS rol_usuario,
     (pg_catalog.current_setting('request.headers',true)::jsonb)->>'x-aquabri-session' AS sesion_token
     INTO STRICT ctx FROM public.usuarios u
     WHERE u.id=public.aq_sesion_legacy_usuario_actual_v1();
  IF NOT aquabri_private.tiene_permiso_usuario(ctx.usuario_id,'gastos') THEN
    RAISE EXCEPTION 'Sin permiso para registrar gastos' USING ERRCODE='42501';
  END IF;
  RETURN public.aq_registrar_gasto_seguro(ctx.sesion_token,ctx.usuario_id,p_nonce,p_gasto);
END;
$function$
;
REVOKE ALL ON FUNCTION public.aq_registrar_gasto_sesion_v1(p_nonce text, p_gasto jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_registrar_gasto_sesion_v1(p_nonce text, p_gasto jsonb) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_registrar_movimiento_envase_sesion_v1(p_nonce text, p_tipo text, p_cantidad integer, p_cliente_id integer DEFAULT NULL::integer, p_fecha date DEFAULT NULL::date, p_notas text DEFAULT ''::text, p_precio_unitario numeric DEFAULT 0, p_medio_pago text DEFAULT 'efectivo'::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
 ctx record; v_prev public.aq_envases_operaciones_auth%rowtype;
 v_payload jsonb;v_fecha date;v_saldo integer;v_bodega integer;
 v_nuevo integer;v_monto numeric;v_venta integer;v_movimiento integer;
 v_tipo text;v_client_id integer;
begin
 select u.id as usuario_id,u.rol as rol_usuario into strict ctx
from public.usuarios u where u.id=public.aq_sesion_legacy_usuario_actual_v1();
 if not aquabri_private.tiene_permiso_usuario(ctx.usuario_id,'envases') then
  raise exception 'Sin permiso para movimientos de envases' using errcode='42501';
 end if;
 if p_tipo not in ('Entrada','Préstamo','Devolución','Venta') then
  raise exception 'Tipo de envases desconocido' using errcode='22023';
 end if;
 if p_tipo in ('Entrada','Venta') and ctx.rol_usuario<>'jefe' then
  raise exception 'Solo jefe puede registrar entradas y ventas de envases desde bodega' using errcode='42501';
 end if;
 if p_nonce is null or length(p_nonce) not between 16 and 120
 or p_cantidad is null or p_cantidad not between 1 and 10000
 or length(coalesce(p_notas,''))>1000
 or p_precio_unitario is null or p_precio_unitario<0 or p_precio_unitario>100000
 or round(p_precio_unitario,2)<>p_precio_unitario
 or p_medio_pago not in ('efectivo','transferencia','otro') then
  raise exception 'Movimiento de envases inválido' using errcode='22023';
 end if;
 v_fecha:=coalesce(p_fecha,(now() at time zone 'America/Guatemala')::date);
 if v_fecha>(now() at time zone 'America/Guatemala')::date
    or v_fecha<(now() at time zone 'America/Guatemala')::date-interval '365 days' then
  raise exception 'Fecha de movimiento inválida' using errcode='22023';
 end if;
 if p_tipo='Venta' and v_fecha<>(now() at time zone 'America/Guatemala')::date then
  raise exception 'Las ventas cobradas se registran con fecha actual de caja' using errcode='22023';
 end if;
 if p_tipo<>'Venta' and p_precio_unitario<>0 then
  raise exception 'El precio solo corresponde a venta de envases' using errcode='22023';
 end if;
 if p_tipo='Venta' and p_precio_unitario<=0 then
  raise exception 'Precio de venta obligatorio' using errcode='22023';
 end if;
 if p_tipo in ('Préstamo','Devolución') and p_cliente_id is null then
  raise exception 'Cliente obligatorio para préstamo o devolución' using errcode='22023';
 end if;
 if p_tipo='Entrada' and p_cliente_id is not null then
  raise exception 'Las entradas se registran sin cliente' using errcode='22023';
 end if;
 v_monto:=p_cantidad*p_precio_unitario;
 v_payload:=pg_catalog.jsonb_build_object('tipo',p_tipo,'cantidad',p_cantidad,
 'cliente_id',p_cliente_id,'fecha',v_fecha,'notas',coalesce(p_notas,''),
 'precio_unitario',p_precio_unitario,'medio_pago',p_medio_pago);
 perform pg_catalog.pg_advisory_xact_lock(20261112,pg_catalog.hashtext(p_nonce));
 select * into v_prev from public.aq_envases_operaciones_auth where nonce=p_nonce for update;
 if found then
   if v_prev.usuario_id<>ctx.usuario_id or v_prev.datos<>v_payload then
     raise exception 'Identificador de operación reutilizado con datos distintos' using errcode='23505';
   end if;
   return v_prev.resultado||pg_catalog.jsonb_build_object('repetida',true);
 end if;
 v_client_id:=p_cliente_id;
 if v_client_id is not null then
    select coalesce(c.envases,0) into v_saldo from public.clientes c
      where c.id=v_client_id and c.archivado_en is null for update;
    if not found then raise exception 'Cliente inactivo o inexistente' using errcode='22023';end if;
    if ctx.rol_usuario<>'jefe' and not public.aq_sesion_legacy_puede_ver_cliente_v1(v_client_id) then
       raise exception 'Cliente no autorizado para este usuario' using errcode='42501';
    end if;
 end if;
 select cantidad into v_bodega from public.envases_bodega where id=1 for update;
 if not found then raise exception 'Bodega de envases no configurada' using errcode='22023';end if;
 if v_bodega is null or v_bodega<0 then raise exception 'Saldo de bodega inválido' using errcode='22023';end if;
 if p_tipo in ('Préstamo','Venta') and v_bodega<p_cantidad then
   raise exception 'Envases insuficientes en bodega: %',v_bodega using errcode='22023';
 end if;
 if p_tipo='Devolución' and coalesce(v_saldo,0)<p_cantidad then
   raise exception 'El cliente no tiene suficientes envases prestados' using errcode='22023';
 end if;
 v_nuevo:=v_bodega+case when p_tipo in ('Entrada','Devolución') then p_cantidad else -p_cantidad end;
 update public.envases_bodega set cantidad=v_nuevo where id=1;
 if p_tipo='Préstamo' then
   update public.clientes set envases=v_saldo+p_cantidad where id=v_client_id;
 elsif p_tipo='Devolución' then
   update public.clientes set envases=v_saldo-p_cantidad where id=v_client_id;
 elsif p_tipo='Venta' then
   insert into public.ventas(fecha,cliente_id,total,pagado,entrega,notas,estado,
     usuario_id,bonificaciones)
   values(v_fecha,v_client_id,v_monto,v_monto,'Entrega Inmediata',
     'Venta de envase vacío ×'||p_cantidad||case when coalesce(p_notas,'')<>'' then ' — '||p_notas else '' end,
     'Entregado',ctx.usuario_id,'')
   returning id into v_venta;
   insert into public.venta_items(venta_id,producto_id,nombre,cant,precio,descuento,bonif_cant)
   values(v_venta,null,'Envase vacío (venta desde bodega)',p_cantidad,p_precio_unitario,0,0);
   insert into public.caja(fecha,tipo,monto,notas,usuario_id,venta_id)
   values(v_fecha,'venta',v_monto,
     'Venta #'||v_venta||' [AQ-MP:'||upper(p_medio_pago)||'] [AQ-ENVASE:'||p_nonce||']',
     ctx.usuario_id,v_venta);
 end if;
 insert into public.envases(fecha,cliente_id,cant,tipo,notas,precio,venta_id,anulado)
 values(v_fecha,v_client_id,p_cantidad,p_tipo,coalesce(p_notas,''),v_monto,v_venta,false)
 returning id into v_movimiento;
 insert into public.aq_envases_operaciones_auth(nonce,usuario_id,datos,resultado)
 values(p_nonce,ctx.usuario_id,v_payload,
   pg_catalog.jsonb_build_object('ok',true,'id',v_movimiento,
    'venta_id',v_venta,'monto',v_monto,'bodega_final',v_nuevo));
 return pg_catalog.jsonb_build_object('ok',true,'repetida',false,'id',v_movimiento,
    'venta_id',v_venta,'monto',v_monto,'bodega_final',v_nuevo);
end;$function$
;
REVOKE ALL ON FUNCTION public.aq_registrar_movimiento_envase_sesion_v1(p_nonce text, p_tipo text, p_cantidad integer, p_cliente_id integer, p_fecha date, p_notas text, p_precio_unitario numeric, p_medio_pago text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_registrar_movimiento_envase_sesion_v1(p_nonce text, p_tipo text, p_cantidad integer, p_cliente_id integer, p_fecha date, p_notas text, p_precio_unitario numeric, p_medio_pago text) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_restaurar_cliente_sesion_v1(p_historial_id integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare ctx record; h public.clientes_eliminados%rowtype; v_id integer; v_original integer; v_json jsonb;
begin
 select u.id AS usuario_id,u.rol AS rol_usuario into strict ctx
   from public.usuarios u where u.id=public.aq_sesion_legacy_usuario_actual_v1();
 if ctx.rol_usuario <> 'jefe' then
   raise exception 'Solo el jefe puede restaurar clientes' using errcode='42501';
 end if;
 select * into h from public.clientes_eliminados where id=p_historial_id for update;
 if not found then raise exception 'Historial inexistente' using errcode='22023'; end if;
 if h.restaurado_en is not null then
   raise exception 'Este cliente ya fue restaurado' using errcode='22023';
 end if;
 v_original:=h.cliente_original_id;
 if v_original is not null and exists(select 1 from public.clientes where id=v_original) then
   update public.clientes set archivado_en=null,archivado_por=null
     where id=v_original and archivado_en is not null returning id into v_id;
   if v_id is null then raise exception 'Cliente ya activo o duplicado' using errcode='22023';end if;
 else
   v_json:=coalesce(h.datos_completos,'{}'::jsonb);
   insert into public.clientes(nombre,telefono,direccion,ruta,lat,lng,
        tiene_exhibidor,descripcion_exhibidor,exhibidor_capacidad,exhibidor_costo,
        fecha_nacimiento,creado_por)
   values(coalesce(nullif(h.nombre,''),'Cliente restaurado'),h.telefono,h.direccion,h.ruta,
       h.lat,h.lng,coalesce(h.tiene_exhibidor,false),v_json->>'descripcion_exhibidor',
       nullif(v_json->>'exhibidor_capacidad','')::integer,
       nullif(v_json->>'exhibidor_costo','')::numeric,
       nullif(v_json->>'fecha_nacimiento','')::date,
       ctx.usuario_id::text) returning id into v_id;
 end if;
 update public.clientes_eliminados set restaurado_en=now() where id=p_historial_id;
 return pg_catalog.jsonb_build_object('ok',true,'id',v_id,'historial_id',p_historial_id);
end;$function$
;
REVOKE ALL ON FUNCTION public.aq_restaurar_cliente_sesion_v1(p_historial_id integer) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_restaurar_cliente_sesion_v1(p_historial_id integer) TO anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_sesion_legacy_empleado_v1()
 RETURNS integer
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 SELECT u.empleado_id FROM public.usuarios u
 WHERE u.id=(SELECT public.aq_sesion_legacy_usuario_actual_v1())
 LIMIT 1
$function$
;
REVOKE ALL ON FUNCTION public.aq_sesion_legacy_empleado_v1() FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.aq_sesion_legacy_empleado_v1() TO anon,authenticated;

-- RLS: clientes archivados se ocultan sin borrar relaciones históricas.
GRANT SELECT ON public.gastos,public.clientes_eliminados TO anon;
-- Verificar existencia de las políticas antes de importarlas como nuevas
-- en un entorno sin las migraciones previas.
COMMIT;
