-- AQUABRI / staging exclusivamente.
-- Pruebas transaccionales y estructurales; no contienen datos personales.
-- Ejecutar con un usuario administrador en SQL Editor de aquabri-staging.
-- La venta se prueba sin JWT: auth.uid() debe ser NULL.
-- Las excepciones de las actualizaciones usan subtransacciones y se deshacen.

DO $qa$
DECLARE
  bloquea_negativo boolean := false;
  bloquea_nulo boolean := false;
  bloquea_venta_sin_auth boolean := false;
BEGIN
  IF (SELECT attnotnull FROM pg_attribute
      WHERE attrelid='public.envases_bodega'::regclass
        AND attname='cantidad') IS DISTINCT FROM TRUE
  THEN RAISE EXCEPTION 'QA: cantidad debe ser NOT NULL'; END IF;

  BEGIN
    UPDATE public.envases_bodega SET cantidad=-1 WHERE id=1;
  EXCEPTION WHEN check_violation THEN
    bloquea_negativo := true;
  END;
  IF NOT bloquea_negativo THEN
    RAISE EXCEPTION 'QA: se aceptó stock negativo';
  END IF;

  BEGIN
    UPDATE public.envases_bodega SET cantidad=NULL WHERE id=1;
  EXCEPTION WHEN not_null_violation THEN
    bloquea_nulo := true;
  END;
  IF NOT bloquea_nulo THEN
    RAISE EXCEPTION 'QA: se aceptó stock nulo';
  END IF;

  IF auth.uid() IS NOT NULL THEN
    RAISE EXCEPTION 'QA: ejecutar comprobación sin JWT';
  END IF;
  BEGIN
    PERFORM public.aq_vender_con_envases_auth_v3(
      '0123456789abcdef', '{}'::jsonb, '[]'::jsonb);
  EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE IN ('28000','42501') THEN
      bloquea_venta_sin_auth := true;
    ELSE
      RAISE;
    END IF;
  END;
  IF NOT bloquea_venta_sin_auth THEN
    RAISE EXCEPTION 'QA: se permitió una venta sin autorización';
  END IF;
END $qa$;

-- Comprobación posterior: el inventario no cambia.
SELECT cantidad AS stock_de_bodega
FROM public.envases_bodega WHERE id=1;

-- Comprobación de que ninguna tabla de public dejó RLS desactivado.
SELECT count(*) AS tablas_sin_rls
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind='r' AND NOT c.relrowsecurity;

-- Las pruebas desde iPhone/Android/PC y las de usuarios reales
-- NO están cubiertas por este script.
