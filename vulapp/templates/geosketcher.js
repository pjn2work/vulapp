document.addEventListener('DOMContentLoaded', () => {
   const canvas = document.getElementById('drawingCanvas');
   const ctx = canvas.getContext('2d');
   const canvasContainer = document.getElementById('canvasContainer');
   const statusMessage = document.getElementById('statusMessage');
   const liveInfoDisplay = document.getElementById('liveInfoDisplay');

   // --- Configuration & State (mostly same) ---
   const SNAP_RADIUS = 10; const ERASE_RADIUS = 10; const POINT_RADIUS = 5; const LINE_WIDTH = 2;
   const COLORS = { point: '#FF0000', snapHighlight: 'rgba(255, 165, 0, 0.7)', preview: '#AAAAAA', eraseHighlight: 'rgba(255, 0, 0, 0.5)' };
   const ZOOM_FACTOR = 1.2;
   const COLOR_PALETTE = ['#0000FF', '#008000', '#FF0000', '#FFA500', '#800080', '#FF00FF', '#00FFFF', '#A52A2A', '#000000', '#808080'];
   let selectedColor = COLOR_PALETTE[0];

   let currentTool = null;
   let tempPoint1 = null;
   let mouseCanvasPos = { x: 0, y: 0 };
   let scale = 1.0; let offsetX = 0; let offsetY = 0; let dpr = window.devicePixelRatio || 1;
   let isShiftDown = false;

   let points = []; let lines = []; let circles = []; let rectangles = []; let triangles = []; let pentagons = []; let hexagons = [];
   let intersectionPoints = []; let nextId = 0;

   function generateId(prefix = 'obj') { return `${prefix}_${nextId++}`; }

   document.addEventListener('keydown', (e) => {
      if (e.key === 'Shift' && !isShiftDown) { isShiftDown = true; if (['rectangle', 'line'].includes(currentTool) && tempPoint1) redrawCanvas(); }
      if (e.key === 'Escape' && tempPoint1) { tempPoint1 = null; redrawCanvas(); }
   });
   document.addEventListener('keyup', (e) => { if (e.key === 'Shift') { isShiftDown = false; if (['rectangle', 'line'].includes(currentTool) && tempPoint1) redrawCanvas(); } });
   window.addEventListener('blur', () => { if (isShiftDown) { isShiftDown = false; if (currentTool === 'rectangle' && tempPoint1) redrawCanvas(); } });

   function resizeCanvas() { /* ... same ... */
      dpr = window.devicePixelRatio || 1;
      const rect = canvasContainer.getBoundingClientRect();
      canvas.width = rect.width * dpr; canvas.height = rect.height * dpr;
      canvas.style.width = `${rect.width}px`; canvas.style.height = `${rect.height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      redrawCanvas();
   }
   window.addEventListener('resize', resizeCanvas);

   function worldToCanvas(worldPos) { return { x: worldPos.x * scale + offsetX, y: worldPos.y * scale + offsetY }; }
   function canvasToWorld(cssCanvasPos) { return { x: (cssCanvasPos.x - offsetX) / scale, y: (cssCanvasPos.y - offsetY) / scale }; }
   function distance(p1, p2) { return Math.sqrt((p1.x - p2.x) ** 2 + (p1.y - p2.y) ** 2); }
   function getRawMouseCanvasPos(event) { const rect = canvas.getBoundingClientRect(); return { x: event.clientX - rect.left, y: event.clientY - rect.top }; }

   function calculatePolygonVertices(center, radius, sides, startAngle = -Math.PI / 2) {
      const vertices = [];
      for (let i = 0; i < sides; i++) {
         const angle = startAngle + (2 * Math.PI * i) / sides;
         vertices.push({
            x: center.x + radius * Math.cos(angle),
            y: center.y + radius * Math.sin(angle)
         });
      }
      return vertices;
   }

   function calculatePolygonFromEdge(p1, p2, sides) {
      // Given an edge from p1 to p2, calculate the center, radius, and starting angle
      // for a regular polygon with 'sides' sides
      const edgeLength = distance(p1, p2);

      // Calculate radius (distance from center to vertex)
      const radius = edgeLength / (2 * Math.sin(Math.PI / sides));

      // Calculate apothem (distance from center to edge midpoint)
      const apothem = edgeLength / (2 * Math.tan(Math.PI / sides));

      // Edge midpoint
      const midX = (p1.x + p2.x) / 2;
      const midY = (p1.y + p2.y) / 2;

      // Edge direction vector
      const edgeX = p2.x - p1.x;
      const edgeY = p2.y - p1.y;

      // Perpendicular vector (rotate 90° counterclockwise for inward direction)
      const perpX = -edgeY / edgeLength;
      const perpY = edgeX / edgeLength;

      // Center position (from midpoint, go inward by apothem distance)
      const center = {
         x: midX + perpX * apothem,
         y: midY + perpY * apothem
      };

      // Calculate the angle from center to p1 (this will be our starting angle)
      const startAngle = Math.atan2(p1.y - center.y, p1.x - center.x);

      return { center, radius, startAngle };
   }

   function getSnapPoint(mouseCSSCanvasCoord) { /* ... same (ensure rect corners are snappable if desired) ... */
      const allSnappableWorldPoints = [
         ...points, ...intersectionPoints,
         ...lines.flatMap(l => [
            { ...l.p1, id: l.p1.id || `lp1_${l.id}` },
            { ...l.p2, id: l.p2.id || `lp2_${l.id}` },
            { x: (l.p1.x + l.p2.x) / 2, y: (l.p1.y + l.p2.y) / 2, id: `lc_${l.id}` }
         ]),
         ...circles.map(c => c.center),
         ...rectangles.flatMap(r => [
            r.p1, r.p2,
            { x: r.p1.x, y: r.p2.y, id: `ic_${r.id}_1` },
            { x: r.p2.x, y: r.p1.y, id: `ic_${r.id}_2` },
            { x: (r.p1.x + r.p2.x) / 2, y: (r.p1.y + r.p2.y) / 2, id: `rc_${r.id}` }
         ]),
         ...triangles.flatMap(t => [
            { ...t.center, id: `tc_${t.id}` },
            ...calculatePolygonVertices(t.center, t.radius, 3, t.startAngle).map((v, i) => ({ ...v, id: `tv_${t.id}_${i}` }))
         ]),
         ...pentagons.flatMap(p => [
            { ...p.center, id: `pc_${p.id}` },
            ...calculatePolygonVertices(p.center, p.radius, 5, p.startAngle).map((v, i) => ({ ...v, id: `pv_${p.id}_${i}` }))
         ]),
         ...hexagons.flatMap(h => [
            { ...h.center, id: `hc_${h.id}` },
            ...calculatePolygonVertices(h.center, h.radius, 6, h.startAngle).map((v, i) => ({ ...v, id: `hv_${h.id}_${i}` }))
         ])
      ].filter((v, i, a) => a.findIndex(t => t.id === v.id) === i); // More robust unique by ID
      let bestSnapPoint = null;
      let minSnapDistSq = SNAP_RADIUS * SNAP_RADIUS;
      for (const worldP of allSnappableWorldPoints) {
         const canvasP = worldToCanvas(worldP);
         const distSq = (mouseCSSCanvasCoord.x - canvasP.x) ** 2 + (mouseCSSCanvasCoord.y - canvasP.y) ** 2;
         if (distSq < minSnapDistSq) { minSnapDistSq = distSq; bestSnapPoint = worldP; }
      }
      if (tempPoint1 && bestSnapPoint && tempPoint1.id && bestSnapPoint.id === tempPoint1.id) {
         const tempPoint1Canvas = worldToCanvas(tempPoint1);
         if (distance(mouseCSSCanvasCoord, tempPoint1Canvas) < SNAP_RADIUS / 2) return canvasToWorld(mouseCSSCanvasCoord);
      }
      return bestSnapPoint ? { ...bestSnapPoint } : canvasToWorld(mouseCSSCanvasCoord);
   }
   function getErasableShapeAt(mouseCSSCanvasCoord) { /* ... same ... */
      const worldMousePos = canvasToWorld(mouseCSSCanvasCoord);
      let closestShape = null; let minDistanceCSS = Infinity;
      const checkDist = (distCSS, shape) => { if (distCSS < minDistanceCSS) { minDistanceCSS = distCSS; closestShape = shape; } };
      points.forEach(p => { const d = distance(worldMousePos, p) * scale; if (d < ERASE_RADIUS) checkDist(d, p); });
      lines.forEach(l => {
         const len2 = (l.p1.x - l.p2.x) ** 2 + (l.p1.y - l.p2.y) ** 2;
         if (len2 === 0) { const d = distance(worldMousePos, l.p1) * scale; if (d < ERASE_RADIUS) checkDist(d, l); return; }
         let t = ((worldMousePos.x - l.p1.x) * (l.p2.x - l.p1.x) + (worldMousePos.y - l.p1.y) * (l.p2.y - l.p1.y)) / len2;
         t = Math.max(0, Math.min(1, t));
         const cp = { x: l.p1.x + t * (l.p2.x - l.p1.x), y: l.p1.y + t * (l.p2.y - l.p1.y) };
         const d = distance(worldMousePos, cp) * scale; if (d < ERASE_RADIUS) checkDist(d, l);
      });
      circles.forEach(c => { const d = Math.abs(distance(worldMousePos, c.center) - c.radius) * scale; if (d < ERASE_RADIUS) checkDist(d, c); });
      rectangles.forEach(r => {
         const minX = Math.min(r.p1.x, r.p2.x); const maxX = Math.max(r.p1.x, r.p2.x);
         const minY = Math.min(r.p1.y, r.p2.y); const maxY = Math.max(r.p1.y, r.p2.y);
         if (worldMousePos.x >= minX && worldMousePos.x <= maxX && worldMousePos.y >= minY && worldMousePos.y <= maxY) checkDist(0, r);
      });
      // Check triangles, pentagons and hexagons by checking distance to their edges
      const checkPolygon = (poly, sides) => {
         const vertices = calculatePolygonVertices(poly.center, poly.radius, sides, poly.startAngle);
         for (let i = 0; i < vertices.length; i++) {
            const p1 = vertices[i];
            const p2 = vertices[(i + 1) % vertices.length];
            const len2 = (p1.x - p2.x) ** 2 + (p1.y - p2.y) ** 2;
            if (len2 === 0) continue;
            let t = ((worldMousePos.x - p1.x) * (p2.x - p1.x) + (worldMousePos.y - p1.y) * (p2.y - p1.y)) / len2;
            t = Math.max(0, Math.min(1, t));
            const cp = { x: p1.x + t * (p2.x - p1.x), y: p1.y + t * (p2.y - p1.y) };
            const d = distance(worldMousePos, cp) * scale;
            if (d < ERASE_RADIUS) { checkDist(d, poly); break; }
         }
      };
      triangles.forEach(t => checkPolygon(t, 3));
      pentagons.forEach(p => checkPolygon(p, 5));
      hexagons.forEach(h => checkPolygon(h, 6));
      return closestShape;
   }


   function lineLineIntersection(l1, l2, checkBounds = true) { /* ... same ... */
      const x1 = l1.p1.x, y1 = l1.p1.y, x2 = l1.p2.x, y2 = l1.p2.y;
      const x3 = l2.p1.x, y3 = l2.p1.y, x4 = l2.p2.x, y4 = l2.p2.y;
      const den = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4);
      if (Math.abs(den) < 1e-9) return null;
      const t = ((x1 - x3) * (y3 - y4) - (y1 - y3) * (x3 - x4)) / den;
      const u = ((x1 - x3) * (y1 - y2) - (y1 - y3) * (x1 - x2)) / den;
      // Only check bounds if requested (and if neither line is marked as infinite)
      if (checkBounds && !l1.infinite && !l2.infinite) {
         if (t < 0 || t > 1 || u < 0 || u > 1) return null;
      }
      return { x: x1 + t * (x2 - x1), y: y1 + t * (y2 - y1) };
   }
   function circleLineIntersection(circle, line) { /* ... same ... */
      const intersections = [];
      const cx = circle.center.x, cy = circle.center.y, r = circle.radius;
      const x1 = line.p1.x, y1 = line.p1.y, x2 = line.p2.x, y2 = line.p2.y;
      const dx = x2 - x1, dy = y2 - y1;
      const A = dx * dx + dy * dy;
      const B = 2 * (dx * (x1 - cx) + dy * (y1 - cy));
      const C = (x1 - cx) * (x1 - cx) + (y1 - cy) * (y1 - cy) - r * r;
      const det = B * B - 4 * A * C;
      if (A <= 1e-9 || det < -1e-9) return intersections;
      if (Math.abs(det) < 1e-9) { const t = -B / (2 * A); intersections.push({ x: x1 + t * dx, y: y1 + t * dy }); }
      else { const t1 = (-B + Math.sqrt(det)) / (2 * A); const t2 = (-B - Math.sqrt(det)) / (2 * A); intersections.push({ x: x1 + t1 * dx, y: y1 + t1 * dy }); intersections.push({ x: x1 + t2 * dx, y: y1 + t2 * dy }); }
      return intersections;
   }
   function circleCircleIntersection(c1, c2) { /* ... same ... */
      const intersections = [];
      const x0 = c1.center.x, y0 = c1.center.y, r0 = c1.radius; const x1 = c2.center.x, y1 = c2.center.y, r1 = c2.radius;
      const d = distance(c1.center, c2.center);
      if (d > r0 + r1 + 1e-9 || d < Math.abs(r0 - r1) - 1e-9 || (d < 1e-9 && Math.abs(r0 - r1) < 1e-9)) return intersections;
      const a = (r0 * r0 - r1 * r1 + d * d) / (2 * d); const hSq = r0 * r0 - a * a; const h = (hSq < 1e-9) ? 0 : Math.sqrt(hSq);
      const x2 = x0 + a * (x1 - x0) / d, y2 = y0 + a * (y1 - y0) / d;
      intersections.push({ x: x2 + h * (y1 - y0) / d, y: y2 - h * (x1 - x0) / d });
      if (h > 1e-9) intersections.push({ x: x2 - h * (y1 - y0) / d, y: y2 + h * (x1 - x0) / d });
      return intersections.filter(p => !isNaN(p.x) && !isNaN(p.y));
   }

   function updateIntersections() {
      intersectionPoints = [];
      let tempIdSuffix = 0;
      const genIntId = (type, id1, id2) => `i_${type}_${id1 ? id1.substring(0, 4) : 'na'}_${id2 ? id2.substring(0, 4) : 'na'}_${tempIdSuffix++}`; // Shorter IDs

      // Line-Line
      for (let i = 0; i < lines.length; i++) {
         for (let j = i + 1; j < lines.length; j++) {
            const p = lineLineIntersection(lines[i], lines[j]);
            if (p) intersectionPoints.push({ ...p, id: genIntId('ll', lines[i].id, lines[j].id), isIntersection: true, type: 'intersectionPoint' });
         }
      }
      // Line-Circle
      lines.forEach(line => {
         circles.forEach(circle => {
            const pts = circleLineIntersection(circle, line);
            pts.forEach(p => intersectionPoints.push({ ...p, id: genIntId('lc', line.id, circle.id), isIntersection: true, type: 'intersectionPoint' }));
         });
      });
      // Circle-Circle
      for (let i = 0; i < circles.length; i++) {
         for (let j = i + 1; j < circles.length; j++) {
            const pts = circleCircleIntersection(circles[i], circles[j]);
            pts.forEach(p => intersectionPoints.push({ ...p, id: genIntId('cc', circles[i].id, circles[j].id), isIntersection: true, type: 'intersectionPoint' }));
         }
      }
      // Triangle-Line intersections
      triangles.forEach(triangle => {
         const vertices = calculatePolygonVertices(triangle.center, triangle.radius, 3, triangle.startAngle);
         lines.forEach(line => {
            for (let i = 0; i < vertices.length; i++) {
               const p1 = vertices[i];
               const p2 = vertices[(i + 1) % vertices.length];
               const edgeLine = { p1, p2 };
               const p = lineLineIntersection(edgeLine, line);
               if (p) intersectionPoints.push({ ...p, id: genIntId('tl', triangle.id, line.id), isIntersection: true, type: 'intersectionPoint' });
            }
         });
      });
      // Pentagon-Line intersections
      pentagons.forEach(pentagon => {
         const vertices = calculatePolygonVertices(pentagon.center, pentagon.radius, 5, pentagon.startAngle);
         lines.forEach(line => {
            for (let i = 0; i < vertices.length; i++) {
               const p1 = vertices[i];
               const p2 = vertices[(i + 1) % vertices.length];
               const edgeLine = { p1, p2 };
               const p = lineLineIntersection(edgeLine, line);
               if (p) intersectionPoints.push({ ...p, id: genIntId('pl', pentagon.id, line.id), isIntersection: true, type: 'intersectionPoint' });
            }
         });
      });
      // Hexagon-Line intersections
      hexagons.forEach(hexagon => {
         const vertices = calculatePolygonVertices(hexagon.center, hexagon.radius, 6, hexagon.startAngle);
         lines.forEach(line => {
            for (let i = 0; i < vertices.length; i++) {
               const p1 = vertices[i];
               const p2 = vertices[(i + 1) % vertices.length];
               const edgeLine = { p1, p2 };
               const p = lineLineIntersection(edgeLine, line);
               if (p) intersectionPoints.push({ ...p, id: genIntId('hl', hexagon.id, line.id), isIntersection: true, type: 'intersectionPoint' });
            }
         });
      });
      // Unique filter
      const uniqueIntersections = [];
      const minSqDistWorld = (SNAP_RADIUS / 2 / scale) ** 2;
      intersectionPoints.forEach(p => {
         if (!uniqueIntersections.some(up => distance(p, up) ** 2 < minSqDistWorld)) {
            uniqueIntersections.push(p);
         }
      });
      intersectionPoints = uniqueIntersections;
      console.log("Intersections updated:", intersectionPoints.length); // Log intersection count
   }


   function drawPoint(worldP, color, cssRadius = POINT_RADIUS) { /* ... same ... */ ctx.beginPath(); ctx.arc(worldP.x, worldP.y, cssRadius / scale, 0, 2 * Math.PI); ctx.fillStyle = color; ctx.fill(); }
   function drawLine(worldL, color, cssWidth = LINE_WIDTH) { /* ... same ... */
      ctx.beginPath();
      ctx.moveTo(worldL.p1.x, worldL.p1.y);
      ctx.lineTo(worldL.p2.x, worldL.p2.y);
      ctx.strokeStyle = color;
      ctx.lineWidth = cssWidth / scale;
      // Use dashed line for infinite intersection lines
      if (worldL.infinite) {
         ctx.setLineDash([5 / scale, 5 / scale]);
      } else {
         ctx.setLineDash([]);
      }
      ctx.stroke();
      ctx.setLineDash([]); // Reset for next draw
   }
   function drawCircle(worldC, color, cssWidth = LINE_WIDTH) { /* ... same ... */ ctx.beginPath(); ctx.arc(worldC.center.x, worldC.center.y, worldC.radius, 0, 2 * Math.PI); ctx.strokeStyle = color; ctx.lineWidth = cssWidth / scale; ctx.stroke(); }
   function drawRectangle(worldR, color, cssWidth = LINE_WIDTH) { /* ... same ... */
      ctx.beginPath();
      const x = Math.min(worldR.p1.x, worldR.p2.x); const y = Math.min(worldR.p1.y, worldR.p2.y);
      const w = Math.abs(worldR.p1.x - worldR.p2.x); const h = Math.abs(worldR.p1.y - worldR.p2.y);
      ctx.rect(x, y, w, h); ctx.strokeStyle = color; ctx.lineWidth = cssWidth / scale; ctx.stroke();
   }
   function drawPolygon(center, radius, sides, color, cssWidth = LINE_WIDTH, startAngle = -Math.PI / 2) {
      const vertices = calculatePolygonVertices(center, radius, sides, startAngle);
      ctx.beginPath();
      ctx.moveTo(vertices[0].x, vertices[0].y);
      for (let i = 1; i < vertices.length; i++) {
         ctx.lineTo(vertices[i].x, vertices[i].y);
      }
      ctx.closePath();
      ctx.strokeStyle = color;
      ctx.lineWidth = cssWidth / scale;
      ctx.stroke();
   }


   function redrawCanvas() {
      ctx.save();
      const cssWidth = parseFloat(canvas.style.width); const cssHeight = parseFloat(canvas.style.height);
      ctx.clearRect(0, 0, cssWidth, cssHeight);
      ctx.translate(offsetX, offsetY); ctx.scale(scale, scale);

      lines.forEach(l => drawLine(l, l.color, LINE_WIDTH));
      circles.forEach(c => drawCircle(c, c.color, LINE_WIDTH));
      rectangles.forEach(r => drawRectangle(r, r.color, LINE_WIDTH));
      triangles.forEach(t => drawPolygon(t.center, t.radius, 3, t.color, LINE_WIDTH, t.startAngle));
      pentagons.forEach(p => drawPolygon(p.center, p.radius, 5, p.color, LINE_WIDTH, p.startAngle));
      hexagons.forEach(h => drawPolygon(h.center, h.radius, 6, h.color, LINE_WIDTH, h.startAngle));

      // Draw vertex/endpoint points for all shapes
      lines.forEach(l => {
         drawPoint(l.p1, COLORS.point, POINT_RADIUS * 0.7);
         drawPoint(l.p2, COLORS.point, POINT_RADIUS * 0.7);
         drawPoint({ x: (l.p1.x + l.p2.x) / 2, y: (l.p1.y + l.p2.y) / 2 }, COLORS.point, POINT_RADIUS * 0.7);
      });
      circles.forEach(c => {
         drawPoint(c.center, COLORS.point, POINT_RADIUS * 0.7);
      });
      rectangles.forEach(r => {
         drawPoint(r.p1, COLORS.point, POINT_RADIUS * 0.7);
         drawPoint(r.p2, COLORS.point, POINT_RADIUS * 0.7);
         drawPoint({ x: r.p1.x, y: r.p2.y }, COLORS.point, POINT_RADIUS * 0.7);
         drawPoint({ x: r.p2.x, y: r.p1.y }, COLORS.point, POINT_RADIUS * 0.7);
         drawPoint({ x: (r.p1.x + r.p2.x) / 2, y: (r.p1.y + r.p2.y) / 2 }, COLORS.point, POINT_RADIUS * 0.7);
      });
      triangles.forEach(t => {
         drawPoint(t.center, COLORS.point, POINT_RADIUS * 0.7);
         const vertices = calculatePolygonVertices(t.center, t.radius, 3, t.startAngle);
         vertices.forEach(v => drawPoint(v, COLORS.point, POINT_RADIUS * 0.7));
      });
      pentagons.forEach(p => {
         drawPoint(p.center, COLORS.point, POINT_RADIUS * 0.7);
         const vertices = calculatePolygonVertices(p.center, p.radius, 5, p.startAngle);
         vertices.forEach(v => drawPoint(v, COLORS.point, POINT_RADIUS * 0.7));
      });
      hexagons.forEach(h => {
         drawPoint(h.center, COLORS.point, POINT_RADIUS * 0.7);
         const vertices = calculatePolygonVertices(h.center, h.radius, 6, h.startAngle);
         vertices.forEach(v => drawPoint(v, COLORS.point, POINT_RADIUS * 0.7));
      });

      points.forEach(p => drawPoint(p, COLORS.point, POINT_RADIUS));
      intersectionPoints.forEach(p => drawPoint(p, COLORS.snapHighlight, POINT_RADIUS * 0.8)); // Ensure this is called

      let liveInfoText = "";

      if (currentTool && tempPoint1) {
         let previewEndPointWorld = getSnapPoint(mouseCanvasPos);
         if (currentTool === 'rectangle' && isShiftDown) {
            const dx = previewEndPointWorld.x - tempPoint1.x; const dy = previewEndPointWorld.y - tempPoint1.y;
            const side = Math.min(Math.abs(dx), Math.abs(dy));
            previewEndPointWorld.x = tempPoint1.x + Math.sign(dx) * side; previewEndPointWorld.y = tempPoint1.y + Math.sign(dy) * side;
         }
         if (currentTool === 'line') { drawLine({ p1: tempPoint1, p2: previewEndPointWorld }, COLORS.preview, LINE_WIDTH * 0.8); liveInfoText = `Length: ${(distance(tempPoint1, previewEndPointWorld)).toFixed(1)}${isShiftDown ? ' (Infinite intersections)' : ''}`; }
         else if (currentTool === 'circle') { const rWorld = distance(tempPoint1, previewEndPointWorld); if (rWorld * scale > 0.1) { drawCircle({ center: tempPoint1, radius: rWorld }, COLORS.preview, LINE_WIDTH * 0.8); liveInfoText = `Radius: ${rWorld.toFixed(1)}`; } }
         else if (currentTool === 'rectangle') { drawRectangle({ p1: tempPoint1, p2: previewEndPointWorld }, COLORS.preview, LINE_WIDTH * 0.8); const w = Math.abs(tempPoint1.x - previewEndPointWorld.x); const h = Math.abs(tempPoint1.y - previewEndPointWorld.y); liveInfoText = `W: ${w.toFixed(1)}, H: ${h.toFixed(1)}`; }
         else if (currentTool === 'triangle') { const edgeLen = distance(tempPoint1, previewEndPointWorld); if (edgeLen * scale > 1) { const poly = calculatePolygonFromEdge(tempPoint1, previewEndPointWorld, 3); drawPolygon(poly.center, poly.radius, 3, COLORS.preview, LINE_WIDTH * 0.8, poly.startAngle); liveInfoText = `Edge: ${edgeLen.toFixed(1)}`; } }
         else if (currentTool === 'pentagon') { const edgeLen = distance(tempPoint1, previewEndPointWorld); if (edgeLen * scale > 1) { const poly = calculatePolygonFromEdge(tempPoint1, previewEndPointWorld, 5); drawPolygon(poly.center, poly.radius, 5, COLORS.preview, LINE_WIDTH * 0.8, poly.startAngle); liveInfoText = `Edge: ${edgeLen.toFixed(1)}`; } }
         else if (currentTool === 'hexagon') { const edgeLen = distance(tempPoint1, previewEndPointWorld); if (edgeLen * scale > 1) { const poly = calculatePolygonFromEdge(tempPoint1, previewEndPointWorld, 6); drawPolygon(poly.center, poly.radius, 6, COLORS.preview, LINE_WIDTH * 0.8, poly.startAngle); liveInfoText = `Edge: ${edgeLen.toFixed(1)}`; } }
      }
      liveInfoDisplay.textContent = liveInfoText;

      if (currentTool === 'eraser') { /* ... same eraser highlight ... */
         const shapeToErase = getErasableShapeAt(mouseCanvasPos);
         if (shapeToErase) {
            const ht = (shapeToErase.type === 'userPoint' ? POINT_RADIUS : (shapeToErase.type === 'rectangle' ? LINE_WIDTH : LINE_WIDTH)) + 4;
            if (shapeToErase.type === 'line') drawLine(shapeToErase, COLORS.eraseHighlight, ht);
            else if (shapeToErase.type === 'circle') drawCircle(shapeToErase, COLORS.eraseHighlight, ht);
            else if (shapeToErase.type === 'rectangle') drawRectangle(shapeToErase, COLORS.eraseHighlight, ht);
            else if (shapeToErase.type === 'triangle') drawPolygon(shapeToErase.center, shapeToErase.radius, 3, COLORS.eraseHighlight, ht, shapeToErase.startAngle);
            else if (shapeToErase.type === 'pentagon') drawPolygon(shapeToErase.center, shapeToErase.radius, 5, COLORS.eraseHighlight, ht, shapeToErase.startAngle);
            else if (shapeToErase.type === 'hexagon') drawPolygon(shapeToErase.center, shapeToErase.radius, 6, COLORS.eraseHighlight, ht, shapeToErase.startAngle);
            else if (shapeToErase.type === 'userPoint') drawPoint(shapeToErase, COLORS.eraseHighlight, ht);
         }
      }
      if (currentTool === 'changeColor') { /* Change color highlight */
         const shapeToRecolor = getErasableShapeAt(mouseCanvasPos);
         if (shapeToRecolor && shapeToRecolor.color !== undefined) {
            const ht = (shapeToRecolor.type === 'userPoint' ? POINT_RADIUS : (shapeToRecolor.type === 'rectangle' ? LINE_WIDTH : LINE_WIDTH)) + 4;
            if (shapeToRecolor.type === 'line') drawLine(shapeToRecolor, selectedColor, ht);
            else if (shapeToRecolor.type === 'circle') drawCircle(shapeToRecolor, selectedColor, ht);
            else if (shapeToRecolor.type === 'rectangle') drawRectangle(shapeToRecolor, selectedColor, ht);
            else if (shapeToRecolor.type === 'triangle') drawPolygon(shapeToRecolor.center, shapeToRecolor.radius, 3, selectedColor, ht, shapeToRecolor.startAngle);
            else if (shapeToRecolor.type === 'pentagon') drawPolygon(shapeToRecolor.center, shapeToRecolor.radius, 5, selectedColor, ht, shapeToRecolor.startAngle);
            else if (shapeToRecolor.type === 'hexagon') drawPolygon(shapeToRecolor.center, shapeToRecolor.radius, 6, selectedColor, ht, shapeToRecolor.startAngle);
         }
      }
      ctx.restore();

      ctx.save(); /* ... same snap highlight drawing ... */
      const currentSnapCandidateWorld = getSnapPoint(mouseCanvasPos);
      const plainMouseWorld = canvasToWorld(mouseCanvasPos);
      const snapToleranceWorld = 0.01 / scale;
      if (currentTool !== 'eraser' && (distance(currentSnapCandidateWorld, plainMouseWorld) > snapToleranceWorld || (currentSnapCandidateWorld.id && plainMouseWorld.id !== currentSnapCandidateWorld.id))) {
         const currentSnapCSS = worldToCanvas(currentSnapCandidateWorld);
         ctx.beginPath(); ctx.arc(currentSnapCSS.x, currentSnapCSS.y, SNAP_RADIUS, 0, 2 * Math.PI); ctx.strokeStyle = COLORS.snapHighlight; ctx.lineWidth = 2; ctx.stroke();
         ctx.beginPath(); ctx.arc(currentSnapCSS.x, currentSnapCSS.y, POINT_RADIUS * 0.6, 0, 2 * Math.PI); ctx.fillStyle = COLORS.snapHighlight; ctx.fill();
      }
      ctx.restore();
   }

   canvas.addEventListener('mousemove', (e) => { mouseCanvasPos = getRawMouseCanvasPos(e); redrawCanvas(); });

   canvas.addEventListener('click', (e) => {
      mouseCanvasPos = getRawMouseCanvasPos(e);
      let clickedWorldPos = getSnapPoint(mouseCanvasPos);

      if (!currentTool) { console.warn("No tool selected for click."); return; }

      if (currentTool === 'rectangle' && tempPoint1 && isShiftDown) {
         const dx = clickedWorldPos.x - tempPoint1.x; const dy = clickedWorldPos.y - tempPoint1.y;
         const side = Math.min(Math.abs(dx), Math.abs(dy));
         clickedWorldPos.x = tempPoint1.x + Math.sign(dx) * side; clickedWorldPos.y = tempPoint1.y + Math.sign(dy) * side;
      }

      switch (currentTool) {
         case 'eraser':
            const shapeToErase = getErasableShapeAt(mouseCanvasPos);
            if (shapeToErase) {
               if (shapeToErase.type === 'line') lines = lines.filter(l => l.id !== shapeToErase.id);
               else if (shapeToErase.type === 'circle') circles = circles.filter(c => c.id !== shapeToErase.id);
               else if (shapeToErase.type === 'rectangle') rectangles = rectangles.filter(r => r.id !== shapeToErase.id);
               else if (shapeToErase.type === 'triangle') triangles = triangles.filter(t => t.id !== shapeToErase.id);
               else if (shapeToErase.type === 'pentagon') pentagons = pentagons.filter(p => p.id !== shapeToErase.id);
               else if (shapeToErase.type === 'hexagon') hexagons = hexagons.filter(h => h.id !== shapeToErase.id);
               else if (shapeToErase.type === 'userPoint') points = points.filter(p => p.id !== shapeToErase.id);
               updateIntersections(); // Call after erase
            }
            break;
         case 'changeColor':
            const shapeToRecolor = getErasableShapeAt(mouseCanvasPos);
            if (shapeToRecolor && shapeToRecolor.color !== undefined) {
               shapeToRecolor.color = selectedColor;
            }
            break;
         case 'point':
            const newPointId = clickedWorldPos.id || generateId('p');
            const newPoint = { ...clickedWorldPos, id: newPointId, type: 'userPoint' };
            let existing = points.find(p => p.id === newPoint.id) || intersectionPoints.find(ip => ip.id === newPoint.id);
            if (!existing && points.every(p => distance(p, newPoint) > 0.01 / scale)) points.push(newPoint);
            // No tempPoint1 for point tool, so it's naturally reset for next shape.
            break;
         case 'line':
            if (!tempPoint1) {
               tempPoint1 = { ...clickedWorldPos, id: clickedWorldPos.id || generateId('_tpl') };
            } else {
               if (distance(tempPoint1, clickedWorldPos) * scale > 1) {
                  lines.push({ p1: tempPoint1, p2: clickedWorldPos, id: generateId('l'), color: selectedColor, type: 'line', infinite: isShiftDown });
                  updateIntersections(); // Call after adding line
               }
               tempPoint1 = null; // FIX: Reset tempPoint1
            }
            break;
         case 'circle':
            if (!tempPoint1) {
               tempPoint1 = { ...clickedWorldPos, id: clickedWorldPos.id || generateId('_tpc') };
            } else {
               const r = distance(tempPoint1, clickedWorldPos);
               if (r * scale > 1) {
                  circles.push({ center: tempPoint1, radius: r, id: generateId('c'), color: selectedColor, type: 'circle' });
                  updateIntersections(); // Call after adding circle
               }
               tempPoint1 = null; // FIX: Reset tempPoint1
            }
            break;
         case 'rectangle':
            if (!tempPoint1) {
               tempPoint1 = { ...clickedWorldPos, id: clickedWorldPos.id || generateId('_tpr') };
            } else {
               if (distance(tempPoint1, clickedWorldPos) * scale > 1) {
                  rectangles.push({ p1: tempPoint1, p2: clickedWorldPos, id: generateId('r'), color: selectedColor, type: 'rectangle' });
                  // No updateIntersections() for rectangles in this simple version
               }
               tempPoint1 = null; // FIX: Reset tempPoint1
            }
            break;
         case 'triangle':
            if (!tempPoint1) {
               tempPoint1 = { ...clickedWorldPos, id: clickedWorldPos.id || generateId('_tpt') };
            } else {
               const edgeLen = distance(tempPoint1, clickedWorldPos);
               if (edgeLen * scale > 1) {
                  const poly = calculatePolygonFromEdge(tempPoint1, clickedWorldPos, 3);
                  triangles.push({ center: poly.center, radius: poly.radius, startAngle: poly.startAngle, id: generateId('tri'), color: selectedColor, type: 'triangle' });
                  updateIntersections(); // Call after adding triangle
               }
               tempPoint1 = null;
            }
            break;
         case 'pentagon':
            if (!tempPoint1) {
               tempPoint1 = { ...clickedWorldPos, id: clickedWorldPos.id || generateId('_tpp') };
            } else {
               const edgeLen = distance(tempPoint1, clickedWorldPos);
               if (edgeLen * scale > 1) {
                  const poly = calculatePolygonFromEdge(tempPoint1, clickedWorldPos, 5);
                  pentagons.push({ center: poly.center, radius: poly.radius, startAngle: poly.startAngle, id: generateId('pent'), color: selectedColor, type: 'pentagon' });
                  updateIntersections(); // Call after adding pentagon
               }
               tempPoint1 = null;
            }
            break;
         case 'hexagon':
            if (!tempPoint1) {
               tempPoint1 = { ...clickedWorldPos, id: clickedWorldPos.id || generateId('_tph') };
            } else {
               const edgeLen = distance(tempPoint1, clickedWorldPos);
               if (edgeLen * scale > 1) {
                  const poly = calculatePolygonFromEdge(tempPoint1, clickedWorldPos, 6);
                  hexagons.push({ center: poly.center, radius: poly.radius, startAngle: poly.startAngle, id: generateId('hex'), color: selectedColor, type: 'hexagon' });
                  updateIntersections(); // Call after adding hexagon
               }
               tempPoint1 = null;
            }
            break;
         default: console.warn("Unknown tool action:", currentTool);
      }
      redrawCanvas();
   });

   const toolButtons = { /* ... same ... */
      toolPoint: document.getElementById('toolPoint'), toolLine: document.getElementById('toolLine'), toolCircle: document.getElementById('toolCircle'), toolRectangle: document.getElementById('toolRectangle'), toolTriangle: document.getElementById('toolTriangle'), toolPentagon: document.getElementById('toolPentagon'), toolHexagon: document.getElementById('toolHexagon'), toolEraser: document.getElementById('toolEraser'), toolChangeColor: document.getElementById('toolChangeColor')
   };
   function setActiveTool(toolName) { /* ... same ... */
      currentTool = toolName; tempPoint1 = null; // Ensure tempPoint1 is always reset
      Object.values(toolButtons).forEach(btn => btn.classList.remove('active'));
      const activeBtnKey = `tool${toolName.charAt(0).toUpperCase() + toolName.slice(1)}`;
      if (toolButtons[activeBtnKey]) toolButtons[activeBtnKey].classList.add('active');

      // Update cursor
      if (toolName === 'changeColor') {
         canvas.classList.add('change-color-cursor');
      } else {
         canvas.classList.remove('change-color-cursor');
      }

      let msg = `Tool: ${toolName}. `;
      if (['line', 'circle', 'rectangle', 'triangle', 'pentagon', 'hexagon'].includes(toolName)) msg += 'Selected Color applies. ';
      if (toolName === 'line') msg += 'Hold Shift for infinite intersections.';
      if (toolName === 'changeColor') msg += 'Click shapes to change to selected color.';
      statusMessage.textContent = msg;
      liveInfoDisplay.textContent = ""; redrawCanvas();
   }
   toolButtons.toolPoint.addEventListener('click', () => setActiveTool('point'));
   toolButtons.toolLine.addEventListener('click', () => setActiveTool('line'));
   toolButtons.toolCircle.addEventListener('click', () => setActiveTool('circle'));
   toolButtons.toolRectangle.addEventListener('click', () => setActiveTool('rectangle'));
   toolButtons.toolTriangle.addEventListener('click', () => setActiveTool('triangle'));
   toolButtons.toolPentagon.addEventListener('click', () => setActiveTool('pentagon'));
   toolButtons.toolHexagon.addEventListener('click', () => setActiveTool('hexagon'));
   toolButtons.toolEraser.addEventListener('click', () => setActiveTool('eraser'));
   toolButtons.toolChangeColor.addEventListener('click', () => setActiveTool('changeColor'));

   const zoomInBtn = document.getElementById('zoomInBtn'); /* ... */
   const zoomOutBtn = document.getElementById('zoomOutBtn'); /* ... */
   const resetViewBtn = document.getElementById('resetViewBtn'); /* ... */
   function zoom(zoomFactor, cssCanvasCenterX, cssCanvasCenterY) { /* ... same ... */
      const worldCenterX_beforeZoom = (cssCanvasCenterX - offsetX) / scale; const worldCenterY_beforeZoom = (cssCanvasCenterY - offsetY) / scale;
      scale *= zoomFactor; scale = Math.max(0.05, Math.min(scale, 100));
      offsetX = cssCanvasCenterX - worldCenterX_beforeZoom * scale; offsetY = cssCanvasCenterY - worldCenterY_beforeZoom * scale;
      updateIntersections(); redrawCanvas(); // updateIntersections on zoom is good
   }
   zoomInBtn.addEventListener('click', () => zoom(ZOOM_FACTOR, parseFloat(canvas.style.width) / 2, parseFloat(canvas.style.height) / 2));
   zoomOutBtn.addEventListener('click', () => zoom(1 / ZOOM_FACTOR, parseFloat(canvas.style.width) / 2, parseFloat(canvas.style.height) / 2));
   resetViewBtn.addEventListener('click', () => {
      // Collect all world coordinates
      const allPoints = [
         ...points,
         ...intersectionPoints,
         ...lines.flatMap(l => [l.p1, l.p2]),
         ...circles.map(c => c.center),
         ...rectangles.flatMap(r => [r.p1, r.p2, { x: r.p1.x, y: r.p2.y }, { x: r.p2.x, y: r.p1.y }]),
         ...triangles.flatMap(t => calculatePolygonVertices(t.center, t.radius, 3, t.startAngle)),
         ...pentagons.flatMap(p => calculatePolygonVertices(p.center, p.radius, 5, p.startAngle)),
         ...hexagons.flatMap(h => calculatePolygonVertices(h.center, h.radius, 6, h.startAngle))
      ];

      // Include circle radii in bounding box
      circles.forEach(c => {
         allPoints.push({ x: c.center.x - c.radius, y: c.center.y });
         allPoints.push({ x: c.center.x + c.radius, y: c.center.y });
         allPoints.push({ x: c.center.x, y: c.center.y - c.radius });
         allPoints.push({ x: c.center.x, y: c.center.y + c.radius });
      });

      if (allPoints.length === 0) {
         // No shapes, reset to default
         scale = 1.0; offsetX = 0; offsetY = 0;
      } else {
         // Find bounding box
         let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
         allPoints.forEach(p => {
            if (p.x < minX) minX = p.x;
            if (p.x > maxX) maxX = p.x;
            if (p.y < minY) minY = p.y;
            if (p.y > maxY) maxY = p.y;
         });

         // Calculate center of bounding box in world coordinates
         const worldCenterX = (minX + maxX) / 2;
         const worldCenterY = (minY + maxY) / 2;

         // Calculate bounding box size
         const worldWidth = maxX - minX;
         const worldHeight = maxY - minY;

         // Canvas size in CSS pixels
         const canvasWidth = parseFloat(canvas.style.width);
         const canvasHeight = parseFloat(canvas.style.height);

         // Calculate scale to fit (with 10% padding)
         const padding = 0.9; // 90% of canvas size = 10% padding
         const scaleX = (canvasWidth * padding) / worldWidth;
         const scaleY = (canvasHeight * padding) / worldHeight;
         scale = Math.min(scaleX, scaleY, 100); // Cap at max zoom
         if (scale < 0.05) scale = 0.05; // Floor at min zoom

         // Calculate offset to center the bounding box
         offsetX = canvasWidth / 2 - worldCenterX * scale;
         offsetY = canvasHeight / 2 - worldCenterY * scale;
      }

      updateIntersections();
      redrawCanvas();
   }); // updateIntersections on reset
   canvas.addEventListener('wheel', (e) => { e.preventDefault(); const zF = e.deltaY < 0 ? ZOOM_FACTOR : 1 / ZOOM_FACTOR; const mP = getRawMouseCanvasPos(e); zoom(zF, mP.x, mP.y); });

   const colorPaletteDiv = document.getElementById('colorPalette');
   COLOR_PALETTE.forEach(color => { /* ... same ... */
      const btn = document.createElement('button'); btn.style.backgroundColor = color; btn.setAttribute('data-color', color); btn.title = color;
      if (color === selectedColor) btn.classList.add('active-color');
      btn.addEventListener('click', () => { selectedColor = color; colorPaletteDiv.querySelector('.active-color')?.classList.remove('active-color'); btn.classList.add('active-color'); });
      colorPaletteDiv.appendChild(btn);
   });
   document.getElementById('clearCanvas').addEventListener('click', () => { /* ... same ... */
      points = []; lines = []; circles = []; rectangles = []; triangles = []; pentagons = []; hexagons = []; intersectionPoints = [];
      tempPoint1 = null; nextId = 0;
      resetViewBtn.click(); // This calls updateIntersections and redraw
   });

   resizeCanvas();
   setActiveTool('point');
});