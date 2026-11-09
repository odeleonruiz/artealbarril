-- SOLO AQUABRI-STAGING. Delegación auditada de permisos por rol y usuario.
-- Requiere migración: qa_roles_predeterminados_y_permisos_individuales_20261109
-- Se preservan firmas, algoritmos de negocio, idempotencia y bloqueos actuales.

-- aq_abrir_caja_auth_v2
CREATE OR REPLACE FUNCTION public.aq_abrir_caja_auth_v2(p_nonce text, p_fecha date, p_monto numeric, p_usuario_caja integer DEFAULT NULL::integer, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
 SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('caja.abrir') THEN
  RAISE EXCEPTION 'Apertura de Caja global temporalmente reservada al jefe mientras se auditan turnos individuales';
 END IF;
 RETURN public.aq_caja_abrir_seguro(ctx.sesion_token,ctx.usuario_id,p_nonce,p_fecha,p_monto,coalesce(p_usuario_caja,ctx.usuario_id::integer),p_notas);
END; $function$;

-- aq_aprobar_vendedor_qa_v1
CREATE OR REPLACE FUNCTION public.aq_aprobar_vendedor_qa_v1(p_solicitud_id bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE boss int; req record; vendor public.usuarios%ROWTYPE;
BEGIN
 boss:=aquabri_private.usuario_id_actual();
 IF boss IS NULL OR NOT EXISTS(SELECT 1 FROM public.usuarios u WHERE u.id=boss AND aquabri_private.tiene_permiso_actual('usuarios.aprobar_qa'))
 THEN RAISE EXCEPTION 'Solo el jefe puede aprobar' USING ERRCODE='42501'; END IF;
 SELECT * INTO req FROM public.aq_solicitudes_vendedor_qa WHERE id=p_solicitud_id FOR UPDATE;
 IF NOT FOUND OR req.estado<>'pendiente' THEN RAISE EXCEPTION 'Solicitud inexistente o no pendiente'; END IF;
 IF NOT EXISTS(SELECT 1 FROM auth.users a WHERE a.id=req.auth_uid AND a.email_confirmed_at IS NOT NULL)
 THEN RAISE EXCEPTION 'La cuenta solicitante ya no está confirmada'; END IF;
 IF EXISTS(SELECT 1 FROM public.usuarios u WHERE u.auth_uid=req.auth_uid) THEN
 RAISE EXCEPTION 'La cuenta ya tiene un usuario vinculado'; END IF;
 SELECT * INTO vendor FROM public.usuarios WHERE id=2 FOR UPDATE;
 IF NOT FOUND OR vendor.rol<>'vendedor' OR vendor.usuario<>'qa_vendedor_nuevo'
 THEN RAISE EXCEPTION 'No se encontró el vendedor ficticio esperado'; END IF;
 IF vendor.auth_uid IS NOT NULL AND EXISTS(SELECT 1 FROM auth.users a WHERE a.id=vendor.auth_uid)
 THEN RAISE EXCEPTION 'El vendedor ya tiene una cuenta Auth real vinculada'; END IF;
 UPDATE public.usuarios SET auth_uid=req.auth_uid WHERE id=2;
 UPDATE public.aq_solicitudes_vendedor_qa SET estado='aprobada',resuelto_en=now(),aprobado_por=boss WHERE id=req.id;
 RETURN jsonb_build_object('solicitud_id',req.id,'usuario_id',2,'rol','vendedor','aprobada',true);
END;$function$;

-- aq_auditoria_fifo_auth_v1
CREATE OR REPLACE FUNCTION public.aq_auditoria_fifo_auth_v1()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record; v_products jsonb; v_sales jsonb; v_totals jsonb;
BEGIN
 SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('inventario.auditar_fifo') THEN RAISE EXCEPTION 'Solo jefe puede ver auditoria FIFO'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',p.id,'producto',p.nombre,'stock',coalesce(p.stock,0),
 'lotes_disponibles',coalesce(x.disponibles,0),'unidades_sin_lote',greatest(coalesce(p.stock,0)-coalesce(x.disponibles,0),0),
 'exceso_lotes',greatest(coalesce(x.disponibles,0)-coalesce(p.stock,0),0),'valor_lotes',coalesce(x.valor,0),'lotes',coalesce(x.num_lotes,0)) ORDER BY p.id),'[]'::jsonb) INTO v_products
 FROM public.productos p LEFT JOIN (
 SELECT producto_id,sum(cantidad_disponible)::int disponibles,sum(cantidad_disponible*costo_unitario) valor,count(*) num_lotes
 FROM public.aq_lotes_inventario GROUP BY producto_id
 ) x ON x.producto_id=p.id WHERE coalesce(p.activo,true)=true;
 SELECT coalesce(jsonb_agg(jsonb_build_object('venta_id',v.id,'fecha',v.fecha,'total',v.total,
 'costo_fifo',coalesce(y.costo,0),'margen_bruto',round(coalesce(v.total,0)-coalesce(y.costo,0),2),
 'unidades_sin_lote',coalesce(y.sin_lote,0),'desglose',coalesce(y.desglose,'[]'::jsonb)) ORDER BY v.id DESC),'[]'::jsonb) INTO v_sales
 FROM (SELECT id,fecha,total FROM public.ventas WHERE estado NOT IN ('Cancelada','Anulado') ORDER BY id DESC LIMIT 15) v
 LEFT JOIN LATERAL (
 SELECT sum(cl.subtotal) costo,
 sum(CASE WHEN cl.lote_id IS NULL THEN cl.cantidad ELSE 0 END) sin_lote,
 jsonb_agg(jsonb_build_object('producto',vi.nombre,'lote_id',cl.lote_id,'cantidad',cl.cantidad,'costo_unitario',cl.costo_unitario,'subtotal',cl.subtotal) ORDER BY cl.id) desglose
 FROM public.venta_items vi JOIN public.aq_consumos_lotes cl ON cl.venta_item_id=vi.id WHERE vi.venta_id=v.id
 ) y ON true;
 SELECT jsonb_build_object(
 'productos_con_diferencia',count(*) FILTER(WHERE coalesce(p.stock,0)<>coalesce(x.disponibles,0)),
 'unidades_sin_lote',coalesce(sum(greatest(coalesce(p.stock,0)-coalesce(x.disponibles,0),0)),0),
 'valor_inventario_lotes',coalesce(sum(x.valor),0)) INTO v_totals
 FROM public.productos p LEFT JOIN (SELECT producto_id,sum(cantidad_disponible) disponibles,sum(cantidad_disponible*costo_unitario) valor FROM public.aq_lotes_inventario GROUP BY producto_id) x ON x.producto_id=p.id
 WHERE coalesce(p.activo,true)=true;
 RETURN jsonb_build_object('productos',v_products,'ventas',v_sales,'resumen',v_totals,'advertencia','Stock sin lote: costo historico no acreditado. Los margenes son brutos, no ganancias netas.');
END; $function$;

-- aq_caja_abrir_qa_jefe_v1
CREATE OR REPLACE FUNCTION public.aq_caja_abrir_qa_jefe_v1(p_nonce text, p_fecha date, p_monto numeric, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
 SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('caja.abrir') THEN RAISE EXCEPTION 'Solo jefe puede abrir Caja QA'; END IF;
 RETURN public.aq_caja_abrir_seguro(ctx.sesion_token,ctx.usuario_id,p_nonce,p_fecha,p_monto,ctx.usuario_id::integer,p_notas);
END;$function$;

-- aq_caja_cerrar_qa_jefe_v1
CREATE OR REPLACE FUNCTION public.aq_caja_cerrar_qa_jefe_v1(p_nonce text, p_fecha date, p_apertura_id integer, p_contado numeric, p_esperado_cliente numeric, p_num_movimientos integer, p_acepta_sin_clasificar boolean, p_acepta_diferencia boolean, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
 SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('caja.cerrar') THEN RAISE EXCEPTION 'Solo jefe puede cerrar Caja QA'; END IF;
 RETURN public.aq_caja_cerrar_seguro(ctx.sesion_token,ctx.usuario_id,p_nonce,p_fecha,p_apertura_id,p_contado,p_esperado_cliente,p_num_movimientos,p_acepta_sin_clasificar,p_acepta_diferencia,p_notas);
END;$function$;

-- aq_caja_resumen_qa_auth_v1
CREATE OR REPLACE FUNCTION public.aq_caja_resumen_qa_auth_v1(p_fecha date)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record; apertura record; ultimo text; m record;
v_total numeric(14,2):=0; qty int:=0; sin_medio int:=0; desconocidos int:=0;
efectivo numeric(14,2):=0; transferencias numeric(14,2):=0; otros numeric(14,2):=0;
medio text; valor numeric(14,2); valido boolean;
BEGIN
 SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('caja.conciliar') THEN RAISE EXCEPTION 'Solo el jefe puede conciliar Caja QA'; END IF;
 IF p_fecha IS NULL THEN RAISE EXCEPTION 'Fecha requerida'; END IF;
 SELECT tipo INTO ultimo FROM public.caja WHERE fecha=p_fecha AND tipo IN ('apertura','cierre') ORDER BY id DESC LIMIT 1;
 SELECT id,monto,usuario_id INTO apertura FROM public.caja WHERE fecha=p_fecha AND tipo='apertura' ORDER BY id DESC LIMIT 1;
 IF apertura.id IS NULL THEN RETURN jsonb_build_object('estado','sin_apertura','fecha',p_fecha,'esperado',null,'movimientos',0); END IF;
 IF ultimo='cierre' THEN RETURN jsonb_build_object('estado','cerrada','fecha',p_fecha,'apertura_id',apertura.id,'esperado',null,'movimientos',0); END IF;
 v_total:=apertura.monto;
 FOR m IN SELECT id,tipo,monto,notas FROM public.caja WHERE fecha=p_fecha AND id>apertura.id ORDER BY id LOOP
  qty:=qty+1;
  valido:=m.tipo IN ('venta','cobro_credito','ingreso','entrada','gasto','egreso','salida','pago_proveedor');
  IF NOT valido THEN desconocidos:=desconocidos+1; CONTINUE; END IF;
  medio:=substring(coalesce(m.notas,'') from '(?i)\[AQ-MP:(EFECTIVO|TRANSFERENCIA|OTRO)\]');
  IF medio IS NULL THEN sin_medio:=sin_medio+1; END IF;
  valor:=CASE WHEN m.tipo IN ('venta','cobro_credito','ingreso','entrada') THEN m.monto ELSE -abs(m.monto) END;
  IF upper(coalesce(medio,''))='TRANSFERENCIA' THEN transferencias:=transferencias+valor;
  ELSIF upper(coalesce(medio,''))='OTRO' THEN otros:=otros+valor;
  ELSE v_total:=v_total+valor; efectivo:=efectivo+valor;
  END IF;
 END LOOP;
 RETURN jsonb_build_object('estado','abierta','fecha',p_fecha,'apertura_id',apertura.id,
  'fondo_inicial',apertura.monto,'movimientos',qty,'sin_medio',sin_medio,'tipos_desconocidos',desconocidos,
  'movimientos_efectivo',efectivo,'movimientos_transferencia',transferencias,'movimientos_otro',otros,
  'esperado',round(v_total,2),'advertencia','Movimientos sin medio se consideran efectivo para el cálculo de cierre y requieren aceptación explícita');
END;$function$;

-- aq_cerrar_caja_auth_v2
CREATE OR REPLACE FUNCTION public.aq_cerrar_caja_auth_v2(p_nonce text, p_fecha date, p_apertura_id integer, p_contado numeric, p_esperado_cliente numeric, p_num_movimientos integer, p_acepta_sin_clasificar boolean DEFAULT false, p_acepta_diferencia boolean DEFAULT false, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record;
BEGIN
 SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('caja.cerrar') THEN
   RAISE EXCEPTION 'Cierre de Caja global temporalmente reservado al jefe mientras se auditan turnos individuales';
 END IF;
 RETURN public.aq_caja_cerrar_seguro(ctx.sesion_token,ctx.usuario_id,p_nonce,p_fecha,p_apertura_id,p_contado,p_esperado_cliente,p_num_movimientos,p_acepta_sin_clasificar,p_acepta_diferencia,p_notas);
END; $function$;

-- aq_cobrar_auth_v2
CREATE OR REPLACE FUNCTION public.aq_cobrar_auth_v2(p_nonce text, p_cliente_id bigint, p_monto numeric, p_medio text, p_notas text, p_credito_id bigint DEFAULT NULL::bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  ctx record;
BEGIN
  SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();

  IF NOT aquabri_private.tiene_permiso_actual('creditos.cobrar') THEN
    RAISE EXCEPTION 'Rol sin permiso para cobrar'
      USING ERRCODE='42501';
  END IF;

  IF p_cliente_id IS NULL OR p_cliente_id <= 0 OR p_cliente_id > 2147483647 THEN
    RAISE EXCEPTION 'Cliente de cobro inválido';
  END IF;

  -- Un vendedor autorizado puede cobrar un crédito de cualquier cliente,
  -- incluso si no creó ni tiene asignado al cliente.
  -- Este permiso NO concede lectura o edición general de los datos del cliente.
  IF p_credito_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.creditos cr
    WHERE cr.id=p_credito_id AND cr.cliente_id=p_cliente_id
  ) THEN
    RAISE EXCEPTION 'Crédito no corresponde a cliente indicado';
  END IF;

  -- Mantener validación de sesión, montos, medio de pago,
  -- idempotencia, bloqueo de saldo y registro de Caja del motor seguro.
  RETURN public.aq_cobrar_credito_seguro(
    ctx.sesion_token, ctx.usuario_id, p_nonce,
    p_cliente_id, p_monto, p_medio, p_notas, p_credito_id
  );
END;
$function$;

-- aq_comprar_auth_v2
CREATE OR REPLACE FUNCTION public.aq_comprar_auth_v2(p_nonce text, p_factura jsonb, p_items jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE c record;
BEGIN
 SELECT * INTO STRICT c FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('compras.registrar') THEN
   RAISE EXCEPTION 'Rol sin permiso para comprar';
 END IF;
 RETURN public.aq_registrar_compra_segura(c.sesion_token,c.usuario_id,p_nonce,p_factura,p_items);
END;$function$;

-- aq_deudas_proveedores_auth_v1
CREATE OR REPLACE FUNCTION public.aq_deudas_proveedores_auth_v1()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE c record; v_result jsonb;
BEGIN
  SELECT * INTO STRICT c FROM aquabri_private.contexto_auth_legacy();
  IF NOT aquabri_private.tiene_permiso_actual('proveedores.ver') THEN RAISE EXCEPTION 'Solo el jefe puede consultar deudas de proveedores'; END IF;
  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'proveedor',proveedor,'concepto',concepto,'monto',monto,'pagado',coalesce(pagado,0),'saldo',round(monto-coalesce(pagado,0),2),'fecha',fecha,'estado',estado) ORDER BY fecha,id),'[]'::jsonb)
    INTO v_result FROM (SELECT id,proveedor,concepto,monto,pagado,fecha,estado FROM public.deudas_proveedores WHERE monto>coalesce(pagado,0) ORDER BY fecha,id LIMIT 200) x;
  RETURN v_result;
END;
$function$;

-- aq_pagar_proveedor_auth_v1
CREATE OR REPLACE FUNCTION public.aq_pagar_proveedor_auth_v1(p_nonce text, p_proveedor text, p_deuda_id bigint, p_monto numeric, p_fecha date, p_notas text, p_origen text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE c record;
BEGIN
  SELECT * INTO STRICT c FROM aquabri_private.contexto_auth_legacy();
  IF NOT aquabri_private.tiene_permiso_actual('proveedores.pagar') THEN RAISE EXCEPTION 'Solo el jefe puede pagar a proveedores'; END IF;
  RETURN public.aq_registrar_pago_proveedor_seguro(c.sesion_token,c.usuario_id,p_nonce,p_proveedor,p_deuda_id,p_monto,p_fecha,p_notas,p_origen);
END;
$function$;

-- aq_solicitudes_vendedor_pendientes_qa_v1
CREATE OR REPLACE FUNCTION public.aq_solicitudes_vendedor_pendientes_qa_v1()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE boss int; result jsonb;
BEGIN
 boss:=aquabri_private.usuario_id_actual();
 IF boss IS NULL OR NOT EXISTS (SELECT 1 FROM public.usuarios u WHERE u.id=boss AND aquabri_private.tiene_permiso_actual('usuarios.aprobar_qa'))
 THEN RAISE EXCEPTION 'Solo el jefe puede revisar solicitudes' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',s.id,'solicitado_en',s.solicitado_en,'estado',s.estado) ORDER BY s.id),'[]'::jsonb)
 INTO result FROM public.aq_solicitudes_vendedor_qa s WHERE s.estado='pendiente';
 RETURN result;
END;$function$;

-- aq_vender_auth_v2
CREATE OR REPLACE FUNCTION public.aq_vender_auth_v2(p_nonce text, p_venta jsonb, p_items jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE ctx record; venta_segura jsonb; cliente_id bigint;
BEGIN
 SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();
 IF NOT aquabri_private.tiene_permiso_actual('ventas.registrar') THEN RAISE EXCEPTION 'Rol sin permiso para vender'; END IF;
 IF p_venta IS NULL OR jsonb_typeof(p_venta)<>'object' THEN RAISE EXCEPTION 'Datos de venta invalidos'; END IF;
 IF nullif(p_venta->>'cliente_id','') IS NOT NULL THEN
  cliente_id:=(p_venta->>'cliente_id')::bigint;
  IF cliente_id<1 OR cliente_id>2147483647 THEN RAISE EXCEPTION 'Cliente invalido'; END IF;
  IF ctx.rol_usuario<>'jefe' AND NOT aquabri_private.puede_ver_cliente(cliente_id::integer) THEN
    RAISE EXCEPTION 'No puedes registrar ventas a clientes no autorizados' USING ERRCODE='42501';
  END IF;
 END IF;
 venta_segura:=jsonb_set(p_venta,'{usuario_id}',to_jsonb(ctx.usuario_id),true);
 RETURN public.aq_registrar_venta_integral_v2(ctx.sesion_token,ctx.usuario_id,p_nonce,venta_segura,p_items);
END; $function$;

-- aq_caja_abrir_seguro
CREATE OR REPLACE FUNCTION public.aq_caja_abrir_seguro(p_token text, p_uid bigint, p_nonce text, p_fecha date, p_monto numeric, p_usuario_caja integer, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE rol text; ultimo text; h text; prev public.aq_caja_operaciones%ROWTYPE;
 idmov integer; resultado jsonb;
BEGIN
 IF coalesce(length(p_token),0)<12 OR coalesce(length(p_nonce),0)<16 OR
    coalesce(length(p_nonce),0)>120 OR p_uid IS NULL OR p_fecha IS NULL OR
    p_monto IS NULL OR p_monto<0 OR p_monto>1000000 OR round(p_monto,2)<>p_monto THEN
    RAISE EXCEPTION 'Datos de apertura invalidos';
 END IF;
 SELECT u.rol INTO rol FROM public.usuarios u JOIN public.sesiones s ON s.usuario_id=u.id
  WHERE s.token=p_token AND u.id=p_uid AND s.expira_en>now() LIMIT 1;
 IF rol IS NULL OR NOT aquabri_private.tiene_permiso_usuario(p_uid::integer,'caja.abrir') THEN
    RAISE EXCEPTION 'Sesion invalida';
 END IF;
 IF coalesce(p_usuario_caja,p_uid::int)<>p_uid AND rol<>'jefe' THEN
    RAISE EXCEPTION 'Solo jefe puede abrir la caja de otra persona';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM public.usuarios WHERE id=coalesce(p_usuario_caja,p_uid::int)) THEN
    RAISE EXCEPTION 'Responsable inexistente';
 END IF;
 IF p_fecha < (now() AT TIME ZONE 'America/Guatemala')::date AND rol<>'jefe' THEN
    RAISE EXCEPTION 'Solo jefe puede registrar apertura historica';
 END IF;
 h:=md5(concat_ws('|',p_fecha,p_monto,p_usuario_caja,coalesce(p_notas,'')));
 PERFORM pg_advisory_xact_lock(hashtext('AQ-CAJA:'||p_fecha::text)::bigint);
 SELECT * INTO prev FROM public.aq_caja_operaciones WHERE nonce=p_nonce;
 IF FOUND THEN
   IF prev.usuario_id<>p_uid OR prev.tipo<>'apertura' OR prev.payload_hash<>h
     THEN RAISE EXCEPTION 'Operacion repetida con datos distintos'; END IF;
   RETURN prev.resultado||jsonb_build_object('repetida',true);
 END IF;
 SELECT tipo INTO ultimo FROM public.caja
 WHERE fecha=p_fecha AND tipo IN ('apertura','cierre')
 ORDER BY id DESC LIMIT 1;
 IF ultimo='apertura' THEN RAISE EXCEPTION 'La caja ya esta abierta'; END IF;
 INSERT INTO public.caja(fecha,tipo,monto,notas,usuario_id)
 VALUES(p_fecha,'apertura',p_monto,
   trim(coalesce(p_notas,'')||' | Apertura SQL QA por usuario #'||p_uid),
   coalesce(p_usuario_caja,p_uid::int)) RETURNING id INTO idmov;
 resultado:=jsonb_build_object('movimiento_id',idmov,'tipo','apertura','monto',p_monto,'repetida',false);
 INSERT INTO public.aq_caja_operaciones(nonce,tipo,usuario_id,movimiento_id,payload_hash,resultado)
 VALUES(p_nonce,'apertura',p_uid,idmov,h,resultado);
 RETURN resultado;
END;$function$;

-- aq_caja_cerrar_seguro
CREATE OR REPLACE FUNCTION public.aq_caja_cerrar_seguro(p_token text, p_uid bigint, p_nonce text, p_fecha date, p_apertura_id integer, p_contado numeric, p_esperado_cliente numeric, p_num_movimientos integer, p_acepta_sin_clasificar boolean DEFAULT false, p_acepta_diferencia boolean DEFAULT false, p_notas text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE rol text; idap integer; fondo numeric; h text; prev public.aq_caja_operaciones%ROWTYPE;
 rowmov record; total numeric:=0; esperado numeric; qty integer:=0; sin_clasificar integer:=0;
 desconocidos integer:=0; medio text; mov numeric; ingreso boolean;
 idmov integer; resultado jsonb; diferencia numeric;
BEGIN
 IF coalesce(length(p_token),0)<12 OR coalesce(length(p_nonce),0)<16 OR
    coalesce(length(p_nonce),0)>120 OR p_uid IS NULL OR p_fecha IS NULL OR p_apertura_id IS NULL
    OR p_contado IS NULL OR round(p_contado,2)<>p_contado OR p_contado<0
    OR p_esperado_cliente IS NULL OR p_num_movimientos IS NULL THEN
    RAISE EXCEPTION 'Datos de cierre invalidos';
 END IF;
 SELECT u.rol INTO rol FROM public.usuarios u JOIN public.sesiones s ON s.usuario_id=u.id
  WHERE s.token=p_token AND u.id=p_uid AND s.expira_en>now() LIMIT 1;
 IF rol IS NULL OR NOT aquabri_private.tiene_permiso_usuario(p_uid::integer,'caja.cerrar') THEN
    RAISE EXCEPTION 'Sesion invalida';
 END IF;
 IF p_fecha < (now() AT TIME ZONE 'America/Guatemala')::date AND rol<>'jefe' THEN
    RAISE EXCEPTION 'Solo jefe puede cerrar una caja historica';
 END IF;
 h:=md5(concat_ws('|',p_fecha,p_apertura_id,p_contado,p_esperado_cliente,
              p_num_movimientos,p_acepta_sin_clasificar,p_acepta_diferencia,coalesce(p_notas,'')));
 PERFORM pg_advisory_xact_lock(hashtext('AQ-CAJA:'||p_fecha::text)::bigint);
 SELECT * INTO prev FROM public.aq_caja_operaciones WHERE nonce=p_nonce;
 IF FOUND THEN
   IF prev.usuario_id<>p_uid OR prev.tipo<>'cierre' OR prev.payload_hash<>h
      THEN RAISE EXCEPTION 'Operacion repetida con datos distintos'; END IF;
   RETURN prev.resultado||jsonb_build_object('repetida',true);
 END IF;
 SELECT id,monto INTO idap,fondo FROM public.caja WHERE fecha=p_fecha AND tipo='apertura'
 ORDER BY id DESC LIMIT 1 FOR UPDATE;
 IF idap IS NULL OR idap<>p_apertura_id THEN RAISE EXCEPTION 'La apertura cambio o no existe'; END IF;
 IF EXISTS(SELECT 1 FROM public.caja WHERE fecha=p_fecha AND tipo='cierre' AND id>idap) THEN
   RAISE EXCEPTION 'Caja ya cerrada';
 END IF;
 total:=fondo;
 FOR rowmov IN SELECT id,tipo,monto,notas FROM public.caja
     WHERE fecha=p_fecha AND id>idap ORDER BY id LOOP
   qty:=qty+1;
   IF rowmov.tipo NOT IN ('venta','cobro_credito','ingreso','entrada','gasto','egreso','salida','pago_proveedor') THEN
     desconocidos:=desconocidos+1;
     CONTINUE;
   END IF;
   medio:=substring(coalesce(rowmov.notas,'') from '(?i)\[AQ-MP:(EFECTIVO|TRANSFERENCIA|OTRO)\]');
   IF medio IS NULL THEN sin_clasificar:=sin_clasificar+1; END IF;
   IF upper(coalesce(medio,'')) IN ('TRANSFERENCIA','OTRO') THEN CONTINUE; END IF;
   ingreso:=rowmov.tipo IN ('venta','cobro_credito','ingreso','entrada');
   mov:=CASE WHEN ingreso THEN rowmov.monto ELSE -abs(rowmov.monto) END;
   total:=total+mov;
 END LOOP;
 esperado:=round(total,2);
 IF qty<>p_num_movimientos OR esperado<>round(p_esperado_cliente,2) THEN
   RAISE EXCEPTION 'Cambios en caja: recalcular movimientos antes de cerrar';
 END IF;
 IF desconocidos>0 THEN RAISE EXCEPTION 'Movimientos de tipo desconocido: revisarlos antes de cerrar'; END IF;
 IF sin_clasificar>0 AND NOT p_acepta_sin_clasificar THEN
   RAISE EXCEPTION 'Hay pagos sin medio identificado; requiere aceptacion';
 END IF;
 diferencia:=round(p_contado-esperado,2);
 IF diferencia<>0 AND NOT p_acepta_diferencia THEN
   RAISE EXCEPTION 'Diferencia de efectivo no confirmada';
 END IF;
 INSERT INTO public.caja(fecha,tipo,monto,notas,usuario_id)
 VALUES(p_fecha,'cierre',p_contado,
    trim(coalesce(p_notas,'')||' | Apertura #'||idap||' | Esperado '||esperado||
        ' | Contado '||p_contado||' | Diferencia '||diferencia||
        ' | Cierre SQL QA usuario #'||p_uid),
    p_uid) RETURNING id INTO idmov;
 resultado:=jsonb_build_object('movimiento_id',idmov,'tipo','cierre',
    'esperado',esperado,'contado',p_contado,'diferencia',diferencia,'repetida',false);
 INSERT INTO public.aq_caja_operaciones(nonce,tipo,usuario_id,movimiento_id,payload_hash,resultado)
 VALUES(p_nonce,'cierre',p_uid,idmov,h,resultado);
 RETURN resultado;
END;$function$;

-- aq_cobrar_credito_seguro
CREATE OR REPLACE FUNCTION public.aq_cobrar_credito_seguro(p_token text, p_uid bigint, p_nonce text, p_cliente_id bigint, p_monto numeric, p_medio text, p_notas text DEFAULT ''::text, p_credito_id bigint DEFAULT NULL::bigint)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_rol text;
  v_cliente_nombre text;
  v_previa public.aq_cobros_credito_operacion%ROWTYPE;
  v_cred public.creditos%ROWTYPE;
  v_hash text;
  v_monto numeric(14,2);
  v_restante numeric(14,2);
  v_saldo numeric(14,2);
  v_abono numeric(14,2);
  v_pagado numeric(14,2);
  v_fecha date := (now() AT TIME ZONE 'America/Guatemala')::date;
  v_caja_id bigint;
  v_detalle jsonb := '[]'::jsonb;
  v_resultado jsonb;
  v_nota text;
  v_medio_txt text;
BEGIN
  IF coalesce(length(p_token),0) < 12 OR p_uid IS NULL OR
     coalesce(length(p_nonce),0) < 16 OR length(p_nonce) > 120 OR
     p_cliente_id IS NULL OR p_cliente_id <= 0 THEN
    RAISE EXCEPTION 'Sesión, cliente o identificador de cobro inválido';
  END IF;

  SELECT u.rol INTO v_rol
  FROM public.sesiones s
  JOIN public.usuarios u ON u.id=s.usuario_id
  WHERE s.token=p_token AND s.usuario_id=p_uid AND s.expira_en>now()
  LIMIT 1;
  IF v_rol IS NULL OR NOT aquabri_private.tiene_permiso_usuario(p_uid::integer,'creditos.cobrar') THEN
    RAISE EXCEPTION 'La sesión no tiene permiso para cobrar créditos';
  END IF;

  IF p_monto IS NULL OR p_monto <= 0 OR p_monto > 100000000 OR
     p_monto <> round(p_monto,2) THEN
    RAISE EXCEPTION 'El importe debe ser positivo y tener como máximo dos decimales';
  END IF;
  IF p_medio IS NULL OR p_medio NOT IN ('efectivo','transferencia','otro') THEN
    RAISE EXCEPTION 'Medio de pago no válido';
  END IF;
  IF length(coalesce(p_notas,'')) > 500 THEN
    RAISE EXCEPTION 'Las observaciones no pueden superar 500 caracteres';
  END IF;
  IF coalesce(p_notas,'') ~* '\[AQ-(MP|CRED-OP):' THEN
    RAISE EXCEPTION 'Las notas no pueden contener marcas internas de pago';
  END IF;
  IF p_credito_id IS NOT NULL AND p_credito_id <= 0 THEN
    RAISE EXCEPTION 'Crédito individual inválido';
  END IF;

  v_monto := round(p_monto,2);
  v_restante := v_monto;
  v_hash := md5(jsonb_build_object(
    'cliente',p_cliente_id,'monto',v_monto,'medio',p_medio,
    'notas',btrim(coalesce(p_notas,'')),'credito',p_credito_id
  )::text);

  -- Evitar dos peticiones simultáneas con la misma clave de operación.
  PERFORM pg_advisory_xact_lock(hashtext('aq_cobro_nonce:'||p_nonce)::bigint);
  SELECT * INTO v_previa FROM public.aq_cobros_credito_operacion
    WHERE nonce=p_nonce;
  IF FOUND THEN
    IF v_previa.usuario_id<>p_uid OR v_previa.cliente_id<>p_cliente_id OR
       v_previa.payload_hash<>v_hash THEN
      RAISE EXCEPTION 'Esta clave de cobro ya pertenece a otra operación';
    END IF;
    RETURN v_previa.resultado || jsonb_build_object('repetida',true);
  END IF;

  SELECT c.nombre INTO v_cliente_nombre
  FROM public.clientes c WHERE c.id=p_cliente_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Cliente # % no encontrado',p_cliente_id;
  END IF;

  -- Un mismo cliente no puede tener dos cobros seguros procesándose a la vez.
  PERFORM pg_advisory_xact_lock(hashtext('aq_cobro_cliente:'||p_cliente_id)::bigint);

  FOR v_cred IN
    SELECT cr.* FROM public.creditos cr
    WHERE cr.cliente_id=p_cliente_id
      AND (p_credito_id IS NULL OR cr.id=p_credito_id)
      AND coalesce(cr.monto,0)>coalesce(cr.pagado,0)
    ORDER BY cr.id ASC
    FOR UPDATE
  LOOP
    EXIT WHEN v_restante <= 0;
    v_saldo := round(v_cred.monto-coalesce(v_cred.pagado,0),2);
    IF v_saldo <= 0 THEN CONTINUE; END IF;
    v_abono := least(v_saldo,v_restante);
    v_pagado := round(coalesce(v_cred.pagado,0)+v_abono,2);

    UPDATE public.creditos
      SET pagado=v_pagado,
          estado=CASE WHEN v_pagado>=v_cred.monto THEN 'Pagado' ELSE 'Pendiente' END
      WHERE id=v_cred.id;

    v_detalle := v_detalle || jsonb_build_array(jsonb_build_object(
      'id',v_cred.id,
      'venta_id',v_cred.venta_id,
      'concepto',v_cred.concepto,
      'fecha',v_cred.fecha,
      'monto',v_cred.monto,
      'abonado',v_abono,
      'saldoAntes',v_saldo,
      'saldoDespues',round(v_saldo-v_abono,2)
    ));
    v_restante := round(v_restante-v_abono,2);
  END LOOP;

  -- Si el saldo cambió, si no existe el crédito o si se intenta cobrar más
  -- de lo pendiente, PostgreSQL revierte todas las actualizaciones anteriores.
  IF v_restante > 0 OR jsonb_array_length(v_detalle)=0 THEN
    RAISE EXCEPTION 'El cobro no se registró: el saldo actual es insuficiente o ya fue pagado. Actualiza Créditos e inténtalo de nuevo.';
  END IF;

  v_medio_txt := CASE p_medio WHEN 'efectivo' THEN 'Efectivo'
    WHEN 'transferencia' THEN 'Transferencia / depósito'
    ELSE 'Tarjeta / otro medio' END;
  v_nota := 'Cobro crédito — ' || coalesce(nullif(btrim(v_cliente_nombre),''),'Cliente #'||p_cliente_id)
    || CASE WHEN btrim(coalesce(p_notas,''))<>'' THEN ' · '||btrim(p_notas) ELSE '' END
    || ' · Medio de pago: '||v_medio_txt||' [AQ-MP:'||upper(p_medio)||']'
    || ' [AQ-CRED-OP:'||p_nonce||']';

  INSERT INTO public.caja(fecha,tipo,monto,notas,usuario_id)
  VALUES (v_fecha,'cobro_credito',v_monto,v_nota,p_uid)
  RETURNING id INTO v_caja_id;

  v_resultado := jsonb_build_object(
    'repetida',false,'cliente_id',p_cliente_id,'monto',v_monto,
    'fecha',v_fecha,'medio',p_medio,'caja_id',v_caja_id,
    'creditos',v_detalle
  );
  INSERT INTO public.aq_cobros_credito_operacion
    (nonce,usuario_id,cliente_id,payload_hash,resultado)
  VALUES(p_nonce,p_uid,p_cliente_id,v_hash,v_resultado);
  RETURN v_resultado;
END;
$function$;

-- aq_registrar_compra_segura
CREATE OR REPLACE FUNCTION public.aq_registrar_compra_segura(p_token text, p_uid bigint, p_nonce text, p_factura jsonb, p_items jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_rol text;
  v_previa record;
  v_fact public.facturas_proveedores%ROWTYPE;
  v_item jsonb;
  v_tipo text;
  v_prov text;
  v_num text;
  v_fecha date;
  v_estado text;
  v_origen text;
  v_notas text;
  v_nombre text;
  v_id bigint;
  v_cant integer;
  v_costo numeric(14,4);
  v_subtotal numeric(14,2);
  v_total numeric(14,2) := 0;
  v_esperado numeric(14,2);
  v_hash text;
  v_existente bigint;
  v_prod public.productos%ROWTYPE;
  v_ins public.insumos%ROWTYPE;
  v_stock_positivo numeric;
  v_costo_orientativo numeric;
  v_retornable text;
  v_bodega numeric;
BEGIN
  -- Autenticación de la sesión personalizada actual de AQUABRI.
  IF p_token IS NULL OR length(p_token) < 12 OR p_uid IS NULL OR
     p_nonce IS NULL OR length(p_nonce) < 16 OR length(p_nonce) > 120 THEN
    RAISE EXCEPTION 'Sesión o identificador de compra inválido';
  END IF;
  SELECT u.rol INTO v_rol
  FROM public.sesiones s JOIN public.usuarios u ON u.id = s.usuario_id
  WHERE s.token = p_token AND s.usuario_id = p_uid AND s.expira_en > now()
  LIMIT 1;
  IF v_rol IS NULL OR NOT aquabri_private.tiene_permiso_usuario(p_uid::integer,'compras.registrar') THEN
    RAISE EXCEPTION 'Usuario sin autorización para registrar facturas de proveedores';
  END IF;
  IF jsonb_typeof(p_factura) <> 'object' OR jsonb_typeof(p_items) <> 'array' OR
     jsonb_array_length(p_items) = 0 OR jsonb_array_length(p_items) > 150 THEN
    RAISE EXCEPTION 'La factura debe incluir entre 1 y 150 productos/insumos/envases';
  END IF;
  v_prov := btrim(coalesce(p_factura->>'proveedor',''));
  v_num := btrim(coalesce(p_factura->>'numero_factura',''));
  v_notas := nullif(btrim(coalesce(p_factura->>'notas','')), '');
  v_estado := p_factura->>'estado';
  v_origen := coalesce(p_factura->>'origen_pago','externo');
  IF length(v_prov) < 2 OR length(v_prov) > 200 THEN
    RAISE EXCEPTION 'Nombre de proveedor inválido';
  END IF;
  IF length(v_num) > 100 THEN RAISE EXCEPTION 'Número de factura demasiado largo'; END IF;
  IF v_estado IS NULL OR v_estado NOT IN ('Pagado','Pendiente','Crédito') THEN
    RAISE EXCEPTION 'Estado de factura inválido';
  END IF;
  IF v_origen NOT IN ('caja','externo') THEN RAISE EXCEPTION 'Origen de pago inválido'; END IF;
  IF v_estado <> 'Pagado' AND v_origen = 'caja' THEN
    RAISE EXCEPTION 'Una factura no pagada no puede generar salida de caja';
  END IF;
  v_fecha := (p_factura->>'fecha')::date;
  IF v_fecha IS NULL THEN RAISE EXCEPTION 'La fecha de factura es obligatoria'; END IF;

  -- Validación de todos los importes antes de insertar registros.
  FOR v_item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
    v_tipo := coalesce(v_item->>'tipo','');
    IF v_tipo NOT IN ('producto','insumo','envase') THEN
      RAISE EXCEPTION 'Tipo de artículo no válido: %', v_tipo;
    END IF;
    v_cant := (v_item->>'cantidad')::integer;
    v_costo := (v_item->>'costo')::numeric;
    v_nombre := btrim(coalesce(v_item->>'nombre',''));
    IF v_cant IS NULL OR v_cant < 1 OR v_cant > 100000 OR
       v_costo IS NULL OR v_costo < 0 OR v_costo > 1000000 OR
       round(v_costo,4) <> v_costo OR length(v_nombre) < 1 OR length(v_nombre)>250 THEN
      RAISE EXCEPTION 'Cantidad, descripción o costo inválido';
    END IF;
    IF v_tipo <> 'envase' AND (v_item->>'id') IS NULL THEN
      RAISE EXCEPTION 'Artículo sin identificador';
    END IF;
    v_subtotal := round(v_cant * v_costo,2);
    v_total := v_total + v_subtotal;
  END LOOP;
  v_esperado := (p_factura->>'total')::numeric;
  IF v_esperado IS NULL OR v_total <> round(v_esperado,2) THEN
    RAISE EXCEPTION 'Total inconsistente. Calculado Q %, enviado Q %',v_total,v_esperado;
  END IF;

  -- Una clave por intento evita dobles compras por doble clic o fallos de red.
  PERFORM pg_advisory_xact_lock(hashtext('aq_compra_nonce:' || p_nonce)::bigint);
  v_hash := md5(p_factura::text || ':' || p_items::text);
  SELECT usuario_id, factura_id, payload_hash INTO v_previa
    FROM public.aq_compras_operacion WHERE nonce=p_nonce;
  IF FOUND THEN
    IF v_previa.usuario_id <> p_uid OR v_previa.payload_hash <> v_hash THEN
      RAISE EXCEPTION 'Este identificador de compra ya corresponde a otra factura';
    END IF;
    RETURN jsonb_build_object('id',v_previa.factura_id,'repetida',true,'total',v_total);
  END IF;

  -- Duplicados contra todo el historial existente: mismo proveedor y número.
  -- Sin número, solo se dispone de protección por nonce.
  IF v_num <> '' THEN
    PERFORM pg_advisory_xact_lock(hashtext('aq_compra_numero:'||lower(v_prov)||':'||lower(v_num))::bigint);
    SELECT f.id INTO v_existente FROM public.facturas_proveedores f
     WHERE lower(btrim(f.proveedor))=lower(v_prov)
       AND lower(btrim(coalesce(f.numero_factura,'')))=lower(v_num)
     ORDER BY f.id DESC LIMIT 1;
    IF FOUND THEN
      RAISE EXCEPTION 'Factura duplicada: % del proveedor % ya está guardada como factura interna #% ',v_num,v_prov,v_existente;
    END IF;
  END IF;

  -- Requerimos el trigger FIFO activo antes de crear nuevos detalles de compra.
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger t
    WHERE t.tgrelid='public.factura_items'::regclass
      AND t.tgname='trg_aq_lote_factura' AND t.tgenabled <> 'D'
  ) THEN
    RAISE EXCEPTION 'Falta el trigger FIFO trg_aq_lote_factura. No se guardó la compra.';
  END IF;

  INSERT INTO public.facturas_proveedores
    (proveedor,numero_factura,fecha,total,estado,notas)
  VALUES (v_prov,nullif(v_num,''),v_fecha,v_total,v_estado,v_notas)
  RETURNING * INTO v_fact;

  FOR v_item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
    v_tipo := v_item->>'tipo';
    v_cant := (v_item->>'cantidad')::integer;
    v_costo := (v_item->>'costo')::numeric;
    v_subtotal := round(v_cant * v_costo,2);
    v_nombre := btrim(v_item->>'nombre');

    IF v_tipo = 'producto' THEN
      v_id := (v_item->>'id')::bigint;
      SELECT * INTO v_prod FROM public.productos WHERE id=v_id FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'Producto # % no encontrado',v_id; END IF;
      INSERT INTO public.factura_items
        (factura_id,producto_id,nombre_producto,cantidad,costo_unit,subtotal)
      VALUES (v_fact.id,v_id,v_nombre,v_cant,v_costo,v_subtotal);
      -- El trigger de factura_items creó el lote FIFO de este producto,
      -- excepto si es retornable (su entrada se registra en bodega de envases).
      v_retornable := lower(btrim(coalesce(v_prod.retornable::text,'')));
      IF v_retornable IN ('si','sí','true','1') THEN
        UPDATE public.envases_bodega SET cantidad=coalesce(cantidad,0)+v_cant
         WHERE id=1 RETURNING cantidad INTO v_bodega;
        IF NOT FOUND THEN RAISE EXCEPTION 'Falta la fila #1 de envases_bodega'; END IF;
        INSERT INTO public.envases(fecha,cliente_id,cant,tipo,notas,precio)
        VALUES(v_fecha,NULL,v_cant,'Entrada',
          'Factura #'||v_fact.id||' — '||v_prov||' ('||v_nombre||')',v_subtotal);
      ELSE
        -- Costo promedio únicamente orientativo en Inventario.
        -- El costo histórico REAL está en aq_lotes_inventario.
        v_stock_positivo := greatest(coalesce(v_prod.stock,0),0);
        v_costo_orientativo := round(
          (v_stock_positivo*greatest(coalesce(v_prod.costo,0),0)+v_cant*v_costo)
          / (v_stock_positivo+v_cant),4);
        UPDATE public.productos
          SET stock=coalesce(stock,0)+v_cant, costo=v_costo_orientativo
          WHERE id=v_id;
      END IF;

    ELSIF v_tipo = 'insumo' THEN
      v_id := (v_item->>'id')::bigint;
      SELECT * INTO v_ins FROM public.insumos WHERE id=v_id FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'Insumo # % no encontrado',v_id; END IF;
      INSERT INTO public.factura_items
        (factura_id,producto_id,nombre_producto,cantidad,costo_unit,subtotal)
      VALUES (v_fact.id,NULL,v_nombre,v_cant,v_costo,v_subtotal);
      UPDATE public.insumos SET stock=coalesce(stock,0)+v_cant, costo=v_costo
       WHERE id=v_id;

    ELSIF v_tipo = 'envase' THEN
      INSERT INTO public.factura_items
        (factura_id,producto_id,nombre_producto,cantidad,costo_unit,subtotal)
      VALUES (v_fact.id,NULL,v_nombre,v_cant,v_costo,v_subtotal);
      UPDATE public.envases_bodega SET cantidad=coalesce(cantidad,0)+v_cant
        WHERE id=1 RETURNING cantidad INTO v_bodega;
      IF NOT FOUND THEN RAISE EXCEPTION 'Falta la fila #1 de envases_bodega'; END IF;
      INSERT INTO public.envases(fecha,cliente_id,cant,tipo,notas,precio)
      VALUES(v_fecha,NULL,v_cant,'Entrada',
        'Factura #'||v_fact.id||' — '||v_prov||' ('||v_nombre||')',v_subtotal);
    END IF;
  END LOOP;

  IF v_estado IN ('Crédito','Pendiente') THEN
    INSERT INTO public.deudas_proveedores
      (proveedor,concepto,monto,pagado,fecha,estado,notas)
    VALUES (v_prov,'Factura #'||v_fact.id,v_total,0,v_fecha,'Pendiente','Auto desde factura');
  ELSIF v_estado = 'Pagado' AND v_origen = 'caja' THEN
    -- Dos vistas del MISMO pago: gasto clasificado como compra (no operativo)
    -- y salida de dinero en caja. Reportes no debe restar la compra como costo otra vez.
    INSERT INTO public.gastos
      (fecha,cat,descripcion,proveedor,monto,notas,usuario_id)
    VALUES (v_fecha,'Compra inventario',
      'Compra de inventario: Factura '||coalesce(nullif(v_num,''),v_fact.id::text)||' de '||v_prov,
      v_prov,v_total,'Auto: Factura #'||v_fact.id,p_uid);
    INSERT INTO public.caja(fecha,tipo,monto,notas,usuario_id)
    VALUES (v_fecha,'gasto',-v_total,
      'Compra inventario Factura #'||v_fact.id||' — '||v_prov,p_uid);
  END IF;

  INSERT INTO public.aq_compras_operacion(nonce,usuario_id,factura_id,payload_hash)
  VALUES(p_nonce,p_uid,v_fact.id,v_hash);

  RETURN jsonb_build_object('id',v_fact.id,'total',v_total,
    'estado',v_estado,'origen_pago',v_origen,'repetida',false);
END;
$function$;

-- aq_registrar_pago_proveedor_seguro
CREATE OR REPLACE FUNCTION public.aq_registrar_pago_proveedor_seguro(p_token text, p_uid bigint, p_nonce text, p_proveedor text, p_deuda_id bigint, p_monto numeric, p_fecha date, p_notas text, p_origen text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
 v_rol text; v_prov text; v_monto numeric(14,2); v_restante numeric(14,2);
 v_hash text; v_prev record; v_deuda record; v_toma numeric(14,2);
 v_pagos integer:=0;
BEGIN
 IF p_token IS NULL OR length(p_token)<12 OR p_uid IS NULL
  OR p_nonce IS NULL OR length(p_nonce)<16 OR length(p_nonce)>120 THEN
   RAISE EXCEPTION 'Sesion invalida';
 END IF;
 SELECT u.rol INTO v_rol FROM public.sesiones s JOIN public.usuarios u ON u.id=s.usuario_id
  WHERE s.token=p_token AND s.usuario_id=p_uid AND s.expira_en>now() LIMIT 1;
 IF v_rol IS NULL OR NOT aquabri_private.tiene_permiso_usuario(p_uid::integer,'proveedores.pagar') THEN
   RAISE EXCEPTION 'Solo el jefe puede registrar pagos a proveedores';
 END IF;
 v_prov:=btrim(coalesce(p_proveedor,''));
 IF length(v_prov)<2 OR length(v_prov)>200 OR p_fecha IS NULL OR p_origen NOT IN ('caja','externo')
   OR p_origen IS NULL OR p_monto IS NULL OR p_monto<=0 OR p_monto>100000000 OR round(p_monto,2)<>p_monto THEN
   RAISE EXCEPTION 'Proveedor, fecha, origen o monto invalido';
 END IF;
 IF p_deuda_id IS NOT NULL AND p_deuda_id<1 THEN RAISE EXCEPTION 'Deuda invalida'; END IF;
 v_monto:=p_monto;v_restante:=v_monto;
 v_hash:=md5(concat_ws('|',v_prov,p_deuda_id::text,v_monto::text,p_fecha::text,
    coalesce(p_notas,''),p_origen));
 PERFORM pg_advisory_xact_lock(hashtext('aq_pago_proveedor:'||lower(v_prov))::bigint);
 SELECT proveedor,monto,usuario_id,payload_hash INTO v_prev
 FROM public.aq_pagos_proveedores WHERE nonce=p_nonce;
 IF FOUND THEN
  IF v_prev.usuario_id<>p_uid OR v_prev.payload_hash<>v_hash THEN
    RAISE EXCEPTION 'Pago duplicado con datos diferentes';
  END IF;
  RETURN jsonb_build_object('repetida',true,'monto',v_prev.monto,'nonce',p_nonce);
 END IF;
 INSERT INTO public.aq_pagos_proveedores(nonce,proveedor,deuda_id,monto,fecha,origen,usuario_id,payload_hash)
 VALUES(p_nonce,v_prov,p_deuda_id,v_monto,p_fecha,p_origen,p_uid,v_hash);
 FOR v_deuda IN
  SELECT id,monto,pagado,estado FROM public.deudas_proveedores
  WHERE lower(btrim(proveedor))=lower(v_prov) AND monto>coalesce(pagado,0)
   AND (p_deuda_id IS NULL OR id=p_deuda_id)
  ORDER BY fecha,id FOR UPDATE
 LOOP
  EXIT WHEN v_restante<=0;
  v_toma:=least(v_restante,round(v_deuda.monto-coalesce(v_deuda.pagado,0),2));
  IF v_toma<=0 THEN CONTINUE; END IF;
  UPDATE public.deudas_proveedores
   SET pagado=coalesce(pagado,0)+v_toma,
       estado=CASE WHEN coalesce(pagado,0)+v_toma>=monto THEN 'Pagado' ELSE 'Pendiente' END
   WHERE id=v_deuda.id;
  INSERT INTO public.aq_pagos_proveedor_detalle(nonce,deuda_id,monto)
  VALUES(p_nonce,v_deuda.id,v_toma);
  v_restante:=v_restante-v_toma;v_pagos:=v_pagos+1;
 END LOOP;
 IF v_restante>0 THEN
  RAISE EXCEPTION 'Pago Q% supera el saldo disponible; operacion revertida por completo',v_monto;
 END IF;
 -- Pagar una deuda NO crea un gasto nuevo. Si sale de caja, una unica salida.
 IF p_origen='caja' THEN
  INSERT INTO public.caja(fecha,tipo,monto,notas,usuario_id)
  VALUES(p_fecha,'gasto',-v_monto,
    'Pago proveedor '||v_prov||' · ref '||p_nonce||
    CASE WHEN length(btrim(coalesce(p_notas,'')))>0 THEN ' — '||left(p_notas,200) ELSE '' END,p_uid);
 END IF;
 RETURN jsonb_build_object('nonce',p_nonce,'monto',v_monto,'deudas_cubiertas',v_pagos,'repetida',false);
END; $function$;

-- aq_registrar_venta_integral_v2
CREATE OR REPLACE FUNCTION public.aq_registrar_venta_integral_v2(p_token text, p_uid bigint, p_nonce text, p_venta jsonb, p_items jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
 urol text; h text; prev public.aq_ventas_integrales_operacion%ROWTYPE;
 result jsonb; vid integer; v public.ventas%ROWTYPE;
 credito boolean; medio text; fecha_pago date; vencimiento date;
 it jsonb; pid integer; qty integer; extra integer; bid integer; qtyprincipal integer;
 cid integer; cash_id integer; credito_id integer; pts numeric(14,2):=0;
 saldo numeric(14,2); punto_id integer; item_pts numeric;
BEGIN
 IF p_token IS NULL OR length(p_token)<12 OR p_uid IS NULL OR p_nonce IS NULL
    OR length(p_nonce)<16 OR length(p_nonce)>120 THEN
    RAISE EXCEPTION 'Autenticacion o identificador de operacion invalidos';
 END IF;
 SELECT u.rol INTO urol
 FROM public.sesiones s JOIN public.usuarios u ON u.id=s.usuario_id
 WHERE s.token=p_token AND s.usuario_id=p_uid AND s.expira_en>now() LIMIT 1;
 IF urol IS NULL OR NOT aquabri_private.tiene_permiso_usuario(p_uid::integer,'ventas.registrar') THEN
    RAISE EXCEPTION 'Usuario no autorizado o sesion vencida';
 END IF;
 IF jsonb_typeof(p_venta)<>'object' OR jsonb_typeof(p_items)<>'array' THEN
    RAISE EXCEPTION 'Payload invalido';
 END IF;
 IF p_venta->>'aq_medio_pago' IS NULL OR
    p_venta->>'aq_medio_pago' NOT IN ('efectivo','transferencia','otro') THEN
    RAISE EXCEPTION 'Medio de pago invalido';
 END IF;
 medio := p_venta->>'aq_medio_pago';
 credito := coalesce((p_venta->>'aq_credito')::boolean,false);
 IF nullif(p_venta->>'aq_fecha_vencimiento','') IS NOT NULL THEN
   vencimiento := (p_venta->>'aq_fecha_vencimiento')::date;
 END IF;
 IF credito AND (nullif(p_venta->>'cliente_id','') IS NULL OR
                  coalesce((p_venta->>'total')::numeric,0)<=0 OR
                  coalesce((p_venta->>'pagado')::numeric,0)<>0) THEN
   RAISE EXCEPTION 'Venta a credito invalida';
 END IF;
 h:=md5(p_venta::text||':'||p_items::text);
 PERFORM pg_advisory_xact_lock(hashtext('AQ-V2:'||p_nonce)::bigint);
 SELECT * INTO prev FROM public.aq_ventas_integrales_operacion WHERE nonce=p_nonce;
 IF FOUND THEN
   IF prev.usuario_id<>p_uid OR prev.payload_hash<>h THEN
     RAISE EXCEPTION 'Identificador reutilizado con datos diferentes';
   END IF;
   RETURN prev.resultado||jsonb_build_object('repetida',true,'integral',true);
 END IF;
 SELECT public.aq_registrar_venta_completa(p_token,p_uid,p_nonce,p_venta,p_items) INTO result;
 IF (result->>'repetida')::boolean THEN
   RAISE EXCEPTION 'Venta V1 preexistente sin V2: conciliar manualmente';
 END IF;
 vid:=(result->>'id')::integer;
 SELECT * INTO STRICT v FROM public.ventas WHERE id=vid;
 IF v.estado IS DISTINCT FROM 'Entregado' AND NOT credito THEN
   RAISE EXCEPTION 'Estado distinto de Entregado requiere flujo de reserva aparte';
 END IF;
 IF NOT credito AND (v.pagado IS DISTINCT FROM v.total) THEN
   RAISE EXCEPTION 'Pago no coincide con el total en venta de contado';
 END IF;
 FOR it IN SELECT value FROM jsonb_array_elements(p_items) LOOP
   pid:=(it->>'producto_id')::integer;
   qty:=(it->>'cant')::integer;
   extra:=coalesce((it->>'bonif_cant')::integer,0);
   bid:=(it->>'bonif_prod_id')::integer;
   qtyprincipal:=qty + CASE WHEN bid IS NULL THEN extra ELSE 0 END;
   UPDATE public.productos SET stock=coalesce(stock,0)-qtyprincipal WHERE id=pid;
   IF NOT FOUND THEN RAISE EXCEPTION 'Producto % inexistente',pid; END IF;
   UPDATE public.insumos i SET stock=coalesce(i.stock,0)-(
     SELECT coalesce(sum(trunc(pi.cant)::integer*qtyprincipal),0)
     FROM public.producto_insumos pi WHERE pi.insumo_id=i.id AND pi.producto_id=pid
   ) WHERE i.id IN (SELECT pi.insumo_id FROM public.producto_insumos pi WHERE pi.producto_id=pid);
   IF bid IS NOT NULL AND extra>0 THEN
     UPDATE public.productos SET stock=coalesce(stock,0)-extra WHERE id=bid;
     IF NOT FOUND THEN RAISE EXCEPTION 'Producto bonificado % inexistente',bid; END IF;
   END IF;
 END LOOP;
 IF credito THEN
   INSERT INTO public.creditos(cliente_id,venta_id,concepto,monto,pagado,fecha,fecha_vencimiento,estado,notas)
   VALUES(v.cliente_id,vid,'Venta #'||vid,v.total,0,v.fecha,vencimiento,'Pendiente','Auto V2 QA')
   RETURNING id INTO credito_id;
 ELSIF v.total>0 THEN
   fecha_pago:=(now() AT TIME ZONE 'America/Guatemala')::date;
   INSERT INTO public.caja(fecha,tipo,monto,notas,usuario_id,venta_id)
   VALUES(fecha_pago,'venta',v.total,
      'Venta #'||vid||' [AQ-MP:'||upper(medio)||'] [AQ-V2:'||p_nonce||']',p_uid,vid)
   RETURNING id INTO cash_id;
 END IF;
 IF NOT credito AND v.cliente_id IS NOT NULL AND EXISTS
    (SELECT 1 FROM public.puntos_config WHERE activo=true) THEN
   SELECT pc.id INTO punto_id
     FROM public.puntos_clientes pc
     WHERE pc.cliente_id=v.cliente_id AND pc.activo=true
     ORDER BY pc.id LIMIT 1 FOR UPDATE;
   IF FOUND THEN
     SELECT coalesce(round(sum(
       (x.item->>'precio')::numeric * (x.item->>'cant')::numeric * pp.porcentaje/100
     ),2),0) INTO pts
     FROM jsonb_array_elements(p_items) AS x(item)
     JOIN public.puntos_productos pp ON pp.producto_id=(x.item->>'producto_id')::integer
     WHERE pp.activo AND pp.porcentaje>0;
     IF pts>0 THEN
       UPDATE public.puntos_clientes SET puntos_totales=coalesce(puntos_totales,0)+pts
       WHERE id=punto_id
       RETURNING round(coalesce(puntos_totales,0)-coalesce(puntos_canjeados,0),2) INTO saldo;
       INSERT INTO public.puntos_historial(cliente_id,venta_id,tipo,puntos,descripcion)
       VALUES(v.cliente_id,vid,'acumulacion',pts,'Venta QA #'||vid);
     END IF;
   END IF;
 END IF;
 result:=result||jsonb_build_object('integral',true,'credito_id',credito_id,
  'caja_id',cash_id,'puntos_ganados',pts,'saldo_puntos',saldo);
 INSERT INTO public.aq_ventas_integrales_operacion(nonce,usuario_id,venta_id,payload_hash,resultado)
 VALUES(p_nonce,p_uid,vid,h,result);
 RETURN result;
END;
$function$;
