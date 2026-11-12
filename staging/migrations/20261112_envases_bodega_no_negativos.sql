-- AQUABRI / Solo laboratorio aquabri-staging
-- Ejecutado y verificado en el proyecto de pruebas el 2026-11-12.
-- No copiar a producción sin respaldo restaurable y pruebas de flujos.
-- No elimina ventas, clientes, créditos, movimientos ni información existente.
-- Requiere que cantidad no tenga nulos ni valores negativos.

BEGIN;
ALTER TABLE public.envases_bodega
  ALTER COLUMN cantidad SET NOT NULL;

DO $guard$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid='public.envases_bodega'::regclass
      AND conname='aq_envases_bodega_cantidad_no_negativa'
  ) THEN
    ALTER TABLE public.envases_bodega
      ADD CONSTRAINT aq_envases_bodega_cantidad_no_negativa
      CHECK (cantidad >= 0);
  END IF;
END $guard$;
COMMIT;
