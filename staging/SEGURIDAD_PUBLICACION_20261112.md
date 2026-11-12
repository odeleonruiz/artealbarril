# AQUABRI — puertas de seguridad antes de producción
Fecha: 2026-11-12. Esta rama es solo para el laboratorio. NO desplegar en producción.

## Aplicado y comprobado
- En aquabri-staging, RLS habilitado en todas las tablas públicas observadas.
- La función `aq_registrar_envases_venta` tiene una comprobación de bodega insuficiente (instalada en el laboratorio; pendiente de versionar también la función completa).
- `envases_bodega.cantidad` ahora es NOT NULL y tiene CHECK (cantidad >= 0).
- Se hicieron dos intentos controlados con cantidad negativa y nula: ambos rechazados.
- La función `aq_vender_con_envases_auth_v3` rechazó una llamada sin autenticación.
- No se borraron ventas ni movimientos con estas pruebas.

## Riesgos aún abiertos
- El proyecto oficial tiene tablas sin RLS activo y roles anónimos con acceso SQL directo.
- Algunas funciones SECURITY DEFINER están expuestas por RPC: revisar una a una sus permisos internos; no revocar indiscriminadamente funciones usadas por la aplicación.
- La aplicación maestra necesita actualizar sus consultas hacia funciones autenticadas antes de endurecer los accesos.
- Un respaldo interno de políticas RLS no equivale al respaldo integral de la base.
- Las pruebas SQL no sustituyen un flujo de ventas completo desde la interfaz.

## Puerta de respaldo para la migración
1. Verificar en Supabase oficial > Database > Backups > Scheduled que exista respaldo diario reciente.
2. Realizar copia lógica independiente con CLI db dump (esquema y datos), bajo almacenamiento protegido.
3. Restaurar esa copia en un entorno aislado y comprobar registros clave: ventas, venta_items, clientes, créditos, caja, envases y proveedores. Contar registros antes/después.
4. No usar una restauración de respaldo sobre el proyecto oficial para probarla.
5. Considerar por separado archivos de Supabase Storage: no se restauran por completo con los backups de PostgreSQL.
6. Preparar rollback de frontend y migraciones reversibles de permisos y RLS, sin eliminación de tablas.

## Pruebas pendientes antes de publicar
- Jefe: venta contado/crédito, cobro, gastos, caja apertura/cierre, compras e inventario, créditos, envases.
- Vendedor: su propia venta, cobro a cliente ajeno cuando corresponde; restringir funciones administrativas.
- Inventario: compras y FIFO; no modificar caja, nómina o permisos sin autorización.
- Envases: entrada, préstamo, devolución, venta, reintento con mismo nonce, rechazar bodega insuficiente.
- Android, iPhone y computadora: iniciar sesión, recargar la página y compartir comprobante.
- Confirmar permisos individuales existentes del sistema oficial antes de migrar.
- Prueba de reversión y comparación completa del historial.

## Fuentes
Documentación oficial Supabase: https://supabase.com/docs/guides/platform/backups
Advertencia SECURITY DEFINER: https://supabase.com/docs/guides/database/database-linter?lint=0029_authenticated_security_definer_function_executable
