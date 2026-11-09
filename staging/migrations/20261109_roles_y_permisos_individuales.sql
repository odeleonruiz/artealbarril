-- AQUABRI Staging: permisos predeterminados por rol y excepciones por usuario.
-- NO aplicar todavía a la base de producción.
CREATE TABLE IF NOT EXISTS public.aq_permisos_catalogo (
  codigo text PRIMARY KEY,
  nombre text NOT NULL,
  grupo text NOT NULL CHECK (grupo IN ('modulo','operacion')),
  delegable boolean NOT NULL DEFAULT true,
  activo boolean NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS public.aq_roles_permisos (
  rol text NOT NULL,
  codigo text NOT NULL REFERENCES public.aq_permisos_catalogo(codigo),
  permitido boolean NOT NULL DEFAULT true,
  PRIMARY KEY (rol,codigo)
);
CREATE TABLE IF NOT EXISTS public.aq_usuarios_permisos (
  usuario_id integer NOT NULL REFERENCES public.usuarios(id),
  codigo text NOT NULL REFERENCES public.aq_permisos_catalogo(codigo),
  permitido boolean NOT NULL,
  actualizado_por integer NOT NULL REFERENCES public.usuarios(id),
  actualizado_en timestamptz NOT NULL DEFAULT now(),
  motivo text,
  PRIMARY KEY (usuario_id,codigo)
);
CREATE TABLE IF NOT EXISTS public.aq_permisos_auditoria (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  usuario_id integer NOT NULL REFERENCES public.usuarios(id),
  codigo text NOT NULL REFERENCES public.aq_permisos_catalogo(codigo),
  valor_anterior boolean,
  valor_nuevo boolean,
  modificado_por integer NOT NULL REFERENCES public.usuarios(id),
  motivo text,
  fecha timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS aq_permisos_auditoria_usuario_fecha ON public.aq_permisos_auditoria(usuario_id,fecha DESC);

INSERT INTO public.aq_permisos_catalogo(codigo,nombre,grupo,delegable)
VALUES
('inicio','Inicio','modulo',true),
('ventas','Ventas','modulo',true),
('clientes','Clientes','modulo',true),
('puntos','Puntos','modulo',true),
('ahorro','Plan de ahorro','modulo',true),
('creditos','Créditos','modulo',true),
('mapa','Mapa de clientes','modulo',true),
('inventario','Inventario','modulo',true),
('envases','Envases','modulo',true),
('activos','Activos','modulo',true),
('facturas','Facturas','modulo',true),
('vehiculos','Vehículos','modulo',true),
('caja','Caja','modulo',true),
('gastos','Gastos','modulo',true),
('metas','Metas','modulo',true),
('reportes','Reportes','modulo',true),
('rrhh','Recursos humanos','modulo',true),
('comisiones','Comisiones','modulo',true),
('usuarios','Usuarios','modulo',true),
('config','Configuración','modulo',true),
('chat','Chat','modulo',true),
('ventas.registrar','Registrar ventas','operacion',true),
('creditos.cobrar','Cobrar créditos','operacion',true),
('compras.registrar','Registrar compras','operacion',true),
('proveedores.ver','Consultar deudas de proveedores','operacion',true),
('proveedores.pagar','Pagar proveedores','operacion',true),
('caja.abrir','Abrir caja global','operacion',true),
('caja.cerrar','Cerrar caja global','operacion',true),
('caja.conciliar','Conciliar caja','operacion',true),
('inventario.auditar_fifo','Auditar costos FIFO','operacion',true),
('usuarios.aprobar_qa','Aprobar acceso de vendedor QA','operacion',true),
('seguridad.permisos','Administrar permisos del personal','operacion',false)
ON CONFLICT (codigo) DO NOTHING;

INSERT INTO public.aq_roles_permisos(rol,codigo,permitido)
SELECT 'jefe',codigo,true FROM public.aq_permisos_catalogo
ON CONFLICT DO NOTHING;
INSERT INTO public.aq_roles_permisos(rol,codigo,permitido)
SELECT 'vendedor', unnest(ARRAY[
'inicio','ventas','puntos','chat','mapa','creditos','caja','vehiculos','gastos','envases',
'ventas.registrar','creditos.cobrar'
]) AS codigo,true ON CONFLICT DO NOTHING;
INSERT INTO public.aq_roles_permisos(rol,codigo,permitido)
SELECT 'vendedor_editor', unnest(ARRAY[
'inicio','ventas','clientes','puntos','chat','mapa','creditos','caja','vehiculos','gastos','envases',
'ventas.registrar','creditos.cobrar'
]) AS codigo,true ON CONFLICT DO NOTHING;
INSERT INTO public.aq_roles_permisos(rol,codigo,permitido)
SELECT 'inventario', unnest(ARRAY[
'inicio','inventario','facturas','chat','compras.registrar'
]) AS codigo,true ON CONFLICT DO NOTHING;

-- Se mantienen las asignaciones legadas de usuarios.permisos_custom.
-- No se sobreescribe ni se limpia esa columna en esta migración.
ALTER TABLE public.aq_permisos_catalogo ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aq_roles_permisos ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aq_usuarios_permisos ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aq_permisos_auditoria ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.aq_permisos_catalogo,public.aq_roles_permisos,
  public.aq_usuarios_permisos,public.aq_permisos_auditoria FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION aquabri_private.tiene_permiso_usuario(p_usuario_id integer,p_codigo text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=''
AS $fn$
SELECT coalesce((
  SELECT CASE
    WHEN u.rol='jefe' THEN true
    WHEN NOT c.delegable THEN false
    ELSE coalesce(o.permitido,r.permitido,false)
  END
  FROM public.usuarios u
  JOIN public.aq_permisos_catalogo c ON c.codigo=p_codigo AND c.activo
  LEFT JOIN public.aq_roles_permisos r ON r.rol=u.rol AND r.codigo=p_codigo
  LEFT JOIN public.aq_usuarios_permisos o ON o.usuario_id=u.id AND o.codigo=p_codigo
  WHERE u.id=p_usuario_id
),false)
$fn$;

CREATE OR REPLACE FUNCTION aquabri_private.tiene_permiso_actual(p_codigo text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=''
AS $fn$
SELECT coalesce((
  SELECT aquabri_private.tiene_permiso_usuario(u.id,p_codigo)
  FROM public.usuarios u WHERE u.auth_uid=(SELECT auth.uid()) LIMIT 1
),false)
$fn$;
REVOKE ALL ON FUNCTION aquabri_private.tiene_permiso_usuario(integer,text) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION aquabri_private.tiene_permiso_actual(text) FROM PUBLIC,anon,authenticated;

CREATE OR REPLACE FUNCTION public.aq_mis_permisos_auth_v1()
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=''
AS $fn$
DECLARE v_usuario public.usuarios%ROWTYPE; v_permisos jsonb;
BEGIN
 SELECT * INTO v_usuario FROM public.usuarios WHERE auth_uid=(SELECT auth.uid());
 IF NOT FOUND THEN
   RAISE EXCEPTION 'Debes iniciar sesión como usuario autorizado' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(jsonb_agg(c.codigo ORDER BY c.codigo),'[]'::jsonb)
 INTO v_permisos FROM public.aq_permisos_catalogo c
 WHERE c.activo AND aquabri_private.tiene_permiso_usuario(v_usuario.id,c.codigo);
 RETURN jsonb_build_object(
   'id',v_usuario.id,'rol',v_usuario.rol,'permisos',v_permisos
 );
END
$fn$;

CREATE OR REPLACE FUNCTION public.aq_permisos_administrar_listar_v1()
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=''
AS $fn$
DECLARE v_jefe integer; v_usuarios jsonb; v_catalogo jsonb; v_roles jsonb; v_excepciones jsonb;
BEGIN
 SELECT id INTO v_jefe FROM public.usuarios
 WHERE auth_uid=(SELECT auth.uid()) AND rol='jefe' LIMIT 1;
 IF v_jefe IS NULL THEN
   RAISE EXCEPTION 'Solo el jefe administra permisos' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',u.id,'nombre',u.nombre,'rol',u.rol) ORDER BY u.nombre),'[]'::jsonb)
 INTO v_usuarios FROM public.usuarios u WHERE u.rol<>'jefe';
 SELECT coalesce(jsonb_agg(jsonb_build_object('codigo',c.codigo,'nombre',c.nombre,'grupo',c.grupo,'delegable',c.delegable) ORDER BY c.grupo,c.codigo),'[]'::jsonb)
 INTO v_catalogo FROM public.aq_permisos_catalogo c WHERE c.activo AND c.delegable;
 SELECT coalesce(jsonb_agg(jsonb_build_object('rol',r.rol,'codigo',r.codigo,'permitido',r.permitido) ORDER BY r.rol,r.codigo),'[]'::jsonb)
 INTO v_roles FROM public.aq_roles_permisos r WHERE r.permitido;
 SELECT coalesce(jsonb_agg(jsonb_build_object('usuario_id',o.usuario_id,'codigo',o.codigo,'permitido',o.permitido) ORDER BY o.usuario_id,o.codigo),'[]'::jsonb)
 INTO v_excepciones FROM public.aq_usuarios_permisos o;
 RETURN jsonb_build_object('usuarios',v_usuarios,'catalogo',v_catalogo,'roles',v_roles,'excepciones',v_excepciones);
END
$fn$;

CREATE OR REPLACE FUNCTION public.aq_asignar_permiso_auth_v1(
  p_usuario_id integer, p_codigo text, p_permitido boolean DEFAULT NULL, p_motivo text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=''
AS $fn$
DECLARE v_jefe integer; v_destino public.usuarios%ROWTYPE; v_anterior boolean; v_existia boolean; v_delegable boolean;
BEGIN
 SELECT id INTO v_jefe FROM public.usuarios
 WHERE auth_uid=(SELECT auth.uid()) AND rol='jefe' LIMIT 1;
 IF v_jefe IS NULL THEN
   RAISE EXCEPTION 'Solo el jefe administra permisos' USING ERRCODE='42501';
 END IF;
 SELECT * INTO v_destino FROM public.usuarios WHERE id=p_usuario_id FOR UPDATE;
 IF NOT FOUND OR v_destino.rol='jefe' THEN
   RAISE EXCEPTION 'Solo se pueden modificar permisos de empleados, no los del jefe' USING ERRCODE='42501';
 END IF;
 SELECT c.delegable INTO v_delegable FROM public.aq_permisos_catalogo c WHERE c.codigo=p_codigo AND c.activo;
 IF NOT FOUND OR NOT v_delegable THEN
   RAISE EXCEPTION 'Permiso inexistente o reservado exclusivamente al jefe' USING ERRCODE='42501';
 END IF;
 IF length(coalesce(p_motivo,''))>250 THEN
   RAISE EXCEPTION 'Motivo demasiado largo';
 END IF;
 SELECT o.permitido INTO v_anterior FROM public.aq_usuarios_permisos o
 WHERE o.usuario_id=p_usuario_id AND o.codigo=p_codigo;
 v_existia:=FOUND;
 IF (p_permitido IS NULL AND NOT v_existia)
   OR (p_permitido IS NOT NULL AND v_existia AND p_permitido=v_anterior) THEN
   RETURN jsonb_build_object('sin_cambios',true,'usuario_id',p_usuario_id,
     'codigo',p_codigo,'efectivo',aquabri_private.tiene_permiso_usuario(p_usuario_id,p_codigo));
 END IF;
 IF p_permitido IS NULL THEN
   DELETE FROM public.aq_usuarios_permisos
     WHERE usuario_id=p_usuario_id AND codigo=p_codigo;
 ELSE
   INSERT INTO public.aq_usuarios_permisos
   (usuario_id,codigo,permitido,actualizado_por,motivo,actualizado_en)
   VALUES(p_usuario_id,p_codigo,p_permitido,v_jefe,p_motivo,now())
   ON CONFLICT (usuario_id,codigo) DO UPDATE SET
     permitido=EXCLUDED.permitido,actualizado_por=EXCLUDED.actualizado_por,
     motivo=EXCLUDED.motivo,actualizado_en=EXCLUDED.actualizado_en;
 END IF;
 INSERT INTO public.aq_permisos_auditoria
 (usuario_id,codigo,valor_anterior,valor_nuevo,modificado_por,motivo)
 VALUES(p_usuario_id,p_codigo,v_anterior,p_permitido,v_jefe,p_motivo);
 RETURN jsonb_build_object('sin_cambios',false,'usuario_id',p_usuario_id,
     'codigo',p_codigo,'permitido',p_permitido,
     'efectivo',aquabri_private.tiene_permiso_usuario(p_usuario_id,p_codigo));
END
$fn$;

REVOKE ALL ON FUNCTION public.aq_mis_permisos_auth_v1() FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.aq_permisos_administrar_listar_v1() FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.aq_asignar_permiso_auth_v1(integer,text,boolean,text) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.aq_mis_permisos_auth_v1() TO authenticated;
GRANT EXECUTE ON FUNCTION public.aq_permisos_administrar_listar_v1() TO authenticated;
GRANT EXECUTE ON FUNCTION public.aq_asignar_permiso_auth_v1(integer,text,boolean,text) TO authenticated;