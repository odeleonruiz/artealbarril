-- AQUABRI / laboratorio de pruebas (artealbarril)
-- 2026-11-09: autorizar cobros de créditos de clientes no asignados
-- Aplicado solamente a aquabri-staging. NO ejecutar en producción
-- sin comparar el esquema, revisar las dependencias y hacer pruebas.
-- No modifica tablas, saldos, movimientos ni historiales.

CREATE OR REPLACE FUNCTION public.aq_cobrar_auth_v2(
  p_nonce text,
  p_cliente_id bigint,
  p_monto numeric,
  p_medio text,
  p_notas text,
  p_credito_id bigint DEFAULT NULL::bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  ctx record;
BEGIN
  SELECT * INTO STRICT ctx FROM aquabri_private.contexto_auth_legacy();

  IF ctx.rol_usuario NOT IN ('jefe','vendedor','vendedor_editor') THEN
    RAISE EXCEPTION 'Rol sin permiso para cobrar'
      USING ERRCODE='42501';
  END IF;

  IF p_cliente_id IS NULL OR p_cliente_id <= 0 OR p_cliente_id > 2147483647 THEN
    RAISE EXCEPTION 'Cliente de cobro inválido';
  END IF;

  -- El vendedor autorizado puede cobrar deudas de cualquier cliente.
  -- No concede privilegios de lectura/edición sobre clientes o ventas.
  IF p_credito_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.creditos cr
    WHERE cr.id=p_credito_id AND cr.cliente_id=p_cliente_id
  ) THEN
    RAISE EXCEPTION 'Crédito no corresponde a cliente indicado';
  END IF;

  -- El motor seguro mantiene validación de importes, sesiones, saldo,
  -- medio de pago, idempotencia, bloqueo e ingreso de Caja.
  RETURN public.aq_cobrar_credito_seguro(
    ctx.sesion_token, ctx.usuario_id, p_nonce,
    p_cliente_id, p_monto, p_medio, p_notas, p_credito_id
  );
END;
$function$;

-- Prueba reversible ya ejecutada en staging: vendedor QA pudo
-- cobrar Q1 de un crédito no asignado en una subtransacción que
-- se revirtió. Saldo restante y cantidad de movimientos sin cambios.
