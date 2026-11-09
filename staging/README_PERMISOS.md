# AQUABRI — permisos por rol con excepciones individuales (Staging)

**Estado:** implementado y probado en `aquabri-staging`; **no** instalado en `aquabri-sistema` de producción.

## Regla de negocio
- Cada cuenta parte con permisos predeterminados según su rol: jefe, vendedor, vendedor_editor o inventario.
- El jefe puede autorizar o bloquear un permiso de **un empleado concreto**, sin modificar a los demás.
- La opción **Predeterminado** elimina la excepción individual y recupera lo establecido por el rol.
- Un empleado no puede administrar sus propios permisos ni los de otra persona.
- Los permisos del jefe no se editan desde esta pantalla, y `seguridad.permisos` nunca es delegable.
- Se registran en `aq_permisos_auditoria` las concesiones, bloqueos y restauraciones efectivas.

## Permisos iniciales
- **Jefe:** todos los módulos y operaciones.
- **Vendedor:** inicio, ventas, puntos, chat, mapa, créditos, caja, vehículos, gastos y envases. Operaciones: registrar ventas y cobrar créditos.
- **Vendedor editor:** permisos de vendedor más módulo de clientes.
- **Inventario:** inicio, inventario, facturas y chat. Operación: registrar compras.
- Los permisos sensibles (cierre de caja, pagos a proveedores, aprobaciones y auditoría FIFO) están desactivados inicialmente para vendedores, pero el jefe puede delegar operaciones concretas.
- Los permisos del *módulo* y de la *operación* son distintos. Dar acceso a `caja` no equivale a autorizar `caja.cerrar`.

## Implementación
- `aq_permisos_catalogo`: catálogo de módulos y operaciones.
- `aq_roles_permisos`: valores predeterminados.
- `aq_usuarios_permisos`: excepciones por empleado.
- `aq_permisos_auditoria`: historial de cambios.
- Funciones privadas `aquabri_private.tiene_permiso_usuario` y `tiene_permiso_actual` evalúan permisos en el servidor.
- RPC autenticados: `aq_mis_permisos_auth_v1`, `aq_permisos_administrar_listar_v1` y `aq_asignar_permiso_auth_v1`.
- Se integraron los controles con **19 funciones** de operaciones y autorizaciones en Staging, incluyendo controles interiores en ventas, cobros, compras y caja.
- El jefe puede gestionar permisos en la pestaña **Administrar permisos QA** de `index.html` del laboratorio.
- Las tablas nuevas tienen RLS habilitado y sin permisos directos a roles del cliente; se opera a través de RPC protegidos.

## Pruebas
- `staging/tests/20261109_auditoria_permisos.sql`: 15 comprobaciones de vendedor, 4 de usuario no vinculado y 4 consultas administrativas del jefe.
- `staging/tests/20261109_permisos_rol_usuario.sql`: rol predeterminado, permisos concedidos/retirados, control efectivo en RPC, restauración y bloqueo de escalamiento.
- Se ejecutaron las pruebas con transacciones `ROLLBACK`: al finalizar quedaron 0 excepciones y 0 registros de auditoría de prueba, 6 ventas y 11 movimientos de caja.

## IMPORTANTE antes de integrar el index maestro
En **producción**, `public.usuarios.permisos_custom` ya contiene listas manuales por usuario. **No reemplazarlas, vaciarlas ni ignorarlas.** Al migrar:
1. Revisar por cada usuario sus permisos efectivos anteriores y preservar los ya concedidos como excepciones (o conciliar con el predeterminado).
2. Reconciliar expresamente los permisos que el jefe había denegado; no activar módulos nuevos automáticamente si eso ampliaría indebidamente el acceso de un empleado real.
3. Adaptar la pantalla principal del jefe y el menú de empleados para leer `aq_mis_permisos_auth_v1`, pero aplicar todas las operaciones sensibles del lado de Supabase.
4. Completar la adaptación de las políticas RLS de lectura y de los módulos que aún están cerrados en Staging. Conceder un módulo por sí solo **no** abre datos que RLS tenga bloqueados.
5. Ejecutar las pruebas por rol, los flujos completos de venta/cobro y una copia de seguridad validada antes de la publicación.
6. No copiar datos de producción al laboratorio sin anonimización ni tocar el `index.html` maestro sin revisión.

## Archivos
- `staging/migrations/20261109_roles_y_permisos_individuales.sql`
- `staging/migrations/20261109_integrar_permisos_operaciones.sql`
- `staging/tests/20261109_permisos_rol_usuario.sql`
- `staging/tests/20261109_auditoria_permisos.sql`

Estas medidas constituyen el primer paso del nuevo modelo de permisos; la publicación sigue pendiente de integración y pruebas de extremo a extremo.
