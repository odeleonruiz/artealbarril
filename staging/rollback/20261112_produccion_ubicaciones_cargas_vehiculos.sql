-- AQUABRI OFICIAL — plan reversible para el cambio RLS realizado el 2026-11-12.
-- REFERENCIA / ROLLBACK MANUAL, NO EJECUTAR salvo caída comprobada.
-- Proyecto afectado: aquabri-sistema, tablas: ubicaciones y cargas_vehiculos.
-- Cambios reales: se eliminó policy acceso_total_ubicaciones (ALL to anon, authenticated, USING true, WITH CHECK true)
-- y se activó RLS en ambas tablas. Ninguna fila fue modificada.
--
-- IMPORTANTE: revertir restaura el estado INSEGURO anterior;
-- solo usar temporalmente si hay una regresión del servicio.
BEGIN;
ALTER TABLE public.ubicaciones DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.cargas_vehiculos DISABLE ROW LEVEL SECURITY;
CREATE POLICY acceso_total_ubicaciones ON public.ubicaciones
  FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
COMMIT;
--
-- Verificar: ambas tablas con relrowsecurity=false y política restituida.
-- No usar este rollback sin comprobar previamente que el problema se origina en estas tablas.
