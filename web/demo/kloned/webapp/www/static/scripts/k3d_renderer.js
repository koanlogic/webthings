/**
 * K3D.Renderer class
 * 
 * Interface for K3D object renderers.
 */
(function()
{
   /**
    * K3D.Renderer Constructor
    */
   K3D.Renderer = function()
   {
   };
   
   /**
    * K3D.Renderer prototype
    */
   K3D.Renderer.prototype =
   {
      /**
       * Sort an object by Z distance in preparation for rendering
       * 
       * @method sortByDistance
       * @param obj {K3D.K3DObject} The object to sort by Z distance
       */
      sortByDistance: function(obj)
      {
      },
      
      /**
       * Render the object artifacts to the given canvas context
       * 
       * @method renderObject
       * @param obj {K3D.K3DObject} The object to render
       * @param ctx {Object} Canvas context
       */
      renderObject: function(obj, ctx)
      {
      }
   };
})();


/**
 * K3D.PointRenderer class
 */
(function()
{
   /**
    * K3D.PointRenderer Constructor
    */
   K3D.PointRenderer = function()
   {
      K3D.PointRenderer.superclass.constructor.call(this);
      
      return this;
   };
   
   extend(K3D.PointRenderer, K3D.Renderer,
   {
      /**
       * Sort an object by Z distance in preparation for rendering
       * 
       * @method sortByDistance
       * @param obj {K3D.K3DObject} The object to sort by Z distance
       */
      sortByDistance: function(obj)
      {
         // quick sort the edges
         if (obj.shademode !== "plain" && obj.sortmode === "sorted")
         {
            // Using a manual quicksort may seem strange, but performance profiling
            // in Chrome has shown this method is x3 faster than the built-in Array
            // sort with the appropriate sorting function applied.
            this.quickSortObject(obj.screencoords, obj.worldcoords, 0, obj.points.length - 1);
         }
      },
      
      /**
       * Reverse quicksort implementation - the points are sorted by Z coordinates
       * 
       * @method quickSortObject
       * @param screencoords {Array} screencoords
       * @param a {Array} array to sort
       * @param left {int} leftindex
       * @param right {int} rightindex
       */
      quickSortObject: function(screencoords, a, left, right)
      {
         var leftIndex = left, rightIndex = right, partionElement;
         var tempP;
         
         if (right > left)
         {
            // get midpoint of the array
            partionElement = a[(left + right) >> 1].z / 2;
            
            // loop through the array until indices cross
            while (leftIndex <= rightIndex)
            {
               // find the first element that is < the partionElement starting
               // from the leftIndex (Z coord of point)
               while (leftIndex < right && a[leftIndex].z > partionElement)
                  leftIndex++;
               
               // find an element that is greater than the
               // partionElement starting from the rightIndex
               while (rightIndex > left && a[rightIndex].z < partionElement)
                  rightIndex--;
               
               // if the indexes have not crossed, swap
               if (leftIndex <= rightIndex)
               {
                  // swap world and screen objects
                  // this is required as points are not an index into worldcoords like
                  // edges and faces - so if worldcoords are swapped, so must be screencoords
                  tempP = screencoords[leftIndex];
                  screencoords[leftIndex] = screencoords[rightIndex];
                  screencoords[rightIndex] = tempP;
                  tempP = a[leftIndex];
                  a[leftIndex] = a[rightIndex];
                  a[rightIndex] = tempP;
                  leftIndex++;
                  rightIndex--;
               }
            }
            
            // if the right index has not reached the left side of the array then
            // must sort the left partition.
            if (left < rightIndex)
            {
               this.quickSortObject(screencoords, a, left, rightIndex);
            }
            
            // if the left index has not reached the left side of the array then 
            // must sort the left partition. 
            if (leftIndex < right)
            {
               this.quickSortObject(screencoords, a, leftIndex, right);
            }
         }
      },
      
      /**
       * Render the object points to the given canvas context
       * 
       * @method renderObject
       * @param obj {K3D.K3DObject} The object to render
       * @param ctx {Object} Canvas context
       */
      renderObject: function(obj, ctx)
      {
         var zdist, c, w;
         var screencoords = obj.screencoords, worldcoords = obj.worldcoords,
             dscale = obj.depthscale, dscalefactor = dscale / 128, linescale = obj.linescale / 255;
         
         for (var i=0, len=obj.points.length; i<len; i++)
         {
            // calculate colour/size to use for shading - based on z distance
            c = worldcoords[i].z + dscale;
            c = c / dscalefactor;
            
            switch (obj.shademode)
            {
               case "lightsource":  // not supported by points, so fallback to plain
               case "plain":
               {
                  ctx.fillStyle = "rgb(" + obj.color[0] + "," + obj.color[1] + "," + obj.color[2] + ")";
                  break;
               }
               
               case "depthcue":
               {
                  if (c < 0) c = 0;
                  else if (c > 255) c = 255;
                  c = 255 - Ceil(c);
                  ctx.fillStyle = obj.depthcueColors[c];
                  break;
               }
            }
            
            // size of point dependant on z distance
            w = linescale * c;
            if (w < 0.1) w = 0.1;
            
            // draw a point
            //ctx.fillRect(screencoords[i].x, screencoords[i].y, w, w);
            ctx.beginPath();
            ctx.arc(screencoords[i].x, screencoords[i].y, w, 0, TWOPI, true);
            ctx.closePath();
            ctx.fill();
         }
      }
   });
})();


/**
 * K3D.WireframeRenderer class
 */
(function()
{
   /**
    * K3D.WireframeRenderer Constructor
    */
   K3D.WireframeRenderer = function()
   {
      K3D.WireframeRenderer.superclass.constructor.call(this);
      
      return this;
   };
   
   extend(K3D.WireframeRenderer, K3D.Renderer,
   {
      /**
       * Sort an object by Z distance in preparation for rendering
       * 
       * @method sortByDistance
       * @param obj {K3D.K3DObject} The object to sort by Z distance
       */
      sortByDistance: function(obj)
      {
         // quick sort the edges
         // TODO: will need sort if take wireframe colours from face edges or similar
         if (obj.shademode !== "plain" && obj.sortmode === "sorted")
         {
            this.quickSortObject(obj.worldcoords, obj.edges, 0, obj.edges.length - 1);
         }
      },
      
      /**
       * Reverse quicksort implementation - the Z coordinates of the edges points are averaged.
       * 
       * @method quickSortObject
       * @param worldcoords {Array} World coordinate list for the object
       * @param a {Array} array to sort
       * @param left {int} leftindex
       * @param right {int} rightindex
       */
      quickSortObject: function(worldcoords, a, left, right)
      {
         var leftIndex = left, rightIndex = right, partionElement;
         var tempEdge;
         
         if (right > left)
         {
            // get midpoint of the array (use as reference to Z coord!)
            partionElement = ((worldcoords[ (a[(left + right) >> 1].a) ].z) +
                              (worldcoords[ (a[(left + right) >> 1].b) ].z)) / 2;
            
            // loop through the array until indices cross
            while (leftIndex <= rightIndex)
            {
               // find the first element that is < the partionElement starting
               // from the leftIndex (average Z coords of edge for element)
               while ((leftIndex < right) &&
                      ((worldcoords[ (a[leftIndex].a) ].z +
                        worldcoords[ (a[leftIndex].b) ].z) / 2 > partionElement))
                  leftIndex++;
               
               // find an element that is greater than the
               // partionElement starting from the rightIndex
               while ((rightIndex > left) &&
                      ((worldcoords[ (a[rightIndex].a) ].z +
                        worldcoords[ (a[rightIndex].b) ].z) / 2 < partionElement))
                  rightIndex--;
               
               // if the indexes have not crossed, swap
               if (leftIndex <= rightIndex)
               {
                  // swap edges objects
                  tempEdge = a[leftIndex];
                  a[leftIndex] = a[rightIndex];
                  a[rightIndex] = tempEdge;
                  leftIndex++;
                  rightIndex--;
               }
            }
            
            // if the right index has not reached the left side of the array then
            // must sort the left partition.
            if (left < rightIndex)
            {
               this.quickSortObject(worldcoords, a, left, rightIndex);
            }
            
            // if the left index has not reached the left side of the array then 
            // must sort the left partition. 
            if (leftIndex < right)
            {
               this.quickSortObject(worldcoords, a, leftIndex, right);
            }
         }
      },
      
      /**
       * Render the edges to the given canvas context
       * 
       * @method renderObject
       * @param obj {K3D.K3DObject} The object to render
       * @param ctx {Object} Canvas context
       */
      renderObject: function(obj, ctx)
      {
         var c, a, b, w;
         var edges = obj.edges, screencoords = obj.screencoords, worldcoords = obj.worldcoords;
         var dscale = obj.depthscale, dscalefactor = dscale / 128, linescale = obj.linescale / 255;
         
         ctx.lineWidth = obj.linescale;
         
         for (var i=0, len=edges.length; i<len; i++)
         {
            a = edges[i].a;
            b = edges[i].b;
            
            switch (obj.shademode)
            {
               case "lightsource":  // not supported by wireframe, so fallback to plain
               case "plain":
               {
                  c = obj.color;
                  ctx.strokeStyle = "rgb(" + c[0] + "," + c[1] + "," + c[2] + ")";
                  break;
               }
               
               case "depthcue":
               {
                  // calculate colour to use for shading
                  c = ((worldcoords[a].z + worldcoords[b].z) / 2) + dscale;
                  c = c / dscalefactor;
                  if (c < 0) c = 0;
                  else if (c > 255) c = 255;
                  c = 255 - Ceil(c);
                  ctx.strokeStyle = obj.depthcueColors[c];
                  w = linescale * c;
                  ctx.lineWidth = (w > 0.1 ? w : 0.1);
                  break;
               }
            }
            
            // draw an edge
            ctx.beginPath();
            ctx.moveTo(screencoords[a].x, screencoords[a].y);
            ctx.lineTo(screencoords[b].x, screencoords[b].y);
            ctx.closePath();
            ctx.stroke();
         }
      }
   });
})();


/**
 * K3D.SolidRenderer class
 */
(function()
{
   /**
    * K3D.SolidRenderer Constructor
    */
   K3D.SolidRenderer = function()
   {
      K3D.SolidRenderer.superclass.constructor.call(this);
      
      return this;
   };
   
   extend(K3D.SolidRenderer, K3D.Renderer,
   {
      /**
       * Sort an object by Z distance in preparation for rendering
       * 
       * @method sortByDistance
       * @param obj {K3D.K3DObject} The object to sort by Z distance
       */
      sortByDistance: function sortByDistance(obj)
      {
         if (obj.sortmode === "sorted")
         {
            this.quickSortObject(obj.worldcoords, obj.faces, 0, obj.faces.length - 1);
         }
      },
      
      /**
       * Reverse quicksort implementation - the Z coordinates of the face points are averaged.
       * 
       * @method quickSortObject
       * @param worldcoords {Array} World coordinate list for the object
       * @param a {Array} array to sort
       * @param left {int} leftindex
       * @param right {int} rightindex
       */
      quickSortObject: function quickSortObject(worldcoords, a, left, right)
      {
         var leftIndex = left, rightIndex = right, partionElement,
             tempFace, vertices, testElement;
         
         if (right > left)
         {
            // get midpoint of the array
            vertices = a[(left + right) >> 1].vertices;
            for (var i=0, j=vertices.length, count=0; i<j; i++)
            {
               count += worldcoords[ vertices[i] ].z;
            }
            partionElement = count / vertices.length;
            
            // loop through the array until indices cross
            while (leftIndex <= rightIndex)
            {
               // find the first element that is < the partionElement starting
               // from the leftIndex (average Z coords of edge for element)
               while (true)
               {
                  vertices = a[leftIndex].vertices;
                  for (var i=0, j=vertices.length, count=0; i<j; i++)
                  {
                     count += (worldcoords[ vertices[i] ].z);
                  }
                  testElement = count / vertices.length;
                  if (leftIndex < right && testElement > partionElement)
                  {
                     leftIndex++;
                  }
                  else
                  {
                     break;
                  }
               }
               
               // find an element that is greater than the
               // partionElement starting from the rightIndex
               while (true)
               {
                  vertices = a[rightIndex].vertices;
                  for (var i=0, j=vertices.length, count=0; i<j; i++)
                  {
                     count += worldcoords[ vertices[i] ].z;
                  }
                  testElement = count / vertices.length;
                  if (rightIndex > left && testElement < partionElement)
                  {
                     rightIndex--;
                  }
                  else
                  {
                     break;
                  }
               }
               
               // if the indexes have not crossed, swap
               if (leftIndex <= rightIndex)
               {
                  // swap face objects
                  tempFace = a[leftIndex];
                  a[leftIndex] = a[rightIndex];
                  a[rightIndex] = tempFace;
                  leftIndex++;
                  rightIndex--;
               }
            }
            
            // if the right index has not reached the left side of the array then
            // must sort the left partition.
            if (left < rightIndex)
            {
               this.quickSortObject(worldcoords, a, left, rightIndex);
            }
            
            // if the left index has not reached the left side of the array then 
            // must sort the left partition. 
            if (leftIndex < right)
            {
               this.quickSortObject(worldcoords, a, leftIndex, right);
            }
         }
      },
      
      /**
       * Render the object faces to the given canvas context
       * 
       * @method renderObject
       * @param obj {K3D.K3DObject} The object to render
       * @param ctx {Object} Canvas context
       */
      renderObject: function renderObject(obj, ctx)
      {
         var faces = obj.faces, screencoords = obj.screencoords, worldcoords = obj.worldcoords;
         var dscale = obj.depthscale, dscalefactor = dscale / 128;
         var viewerVector = new Vector3D(0, 0, 1);
         var vertices, r,g,b,c, PIDIV2 = PI/2, fillStyle;
         var lights = obj.controller.lights;
         var doublesided = obj.doublesided;
         
         for (var n=0, len=faces.length, face; n<len; n++)
         {
            face = faces[n];
            vertices = face.vertices;
            
            // perform hidden surface removal first - discard non visible faces
            // angle test is adjusted slightly to account for perspective
            // TODO: this value should be based on the perspective level...
            var angle = viewerVector.thetaTo2(face.worldnormal);
            if (doublesided || (angle + 0.15 > PIDIV2))
            {
               switch (obj.shademode)
               {
                  case "plain":
                  {
                     if (face.texture === null)
                     {
                        // apply plain colour directly from poly
                        c = face.color;
                        fillStyle = "rgb(" + c[0] + "," + c[1] + "," + c[2] + ")";
                        this.renderPolygon(ctx, obj, face, fillStyle)
                     }
                     else
                     {
                        this.renderPolygon(ctx, obj, face);
                     }
                     break;
                  }
                  
                  case "depthcue":
                  {
                     // calculate colour to use based on av Z distance of polygon
                     for (var i=0, j=vertices.length, count=0; i<j; i++)
                     {
                        count += worldcoords[ vertices[i] ].z;
                     }
                     var col = ((count / vertices.length) + dscale) / dscalefactor;
                     if (col < 0) col = 0;
                     else if (col > 255) col = 255;
                     if (face.texture === null)
                     {
                        // plain depth cued colour fill
                        col = (255 - col) / 255;
                        c = face.color;
                        r = Ceil(col * c[0]);
                        g = Ceil(col * c[1]);
                        b = Ceil(col * c[2]);
                        fillStyle = "rgb(" + r + "," + g + "," + b + ")";
                     }
                     else
                     {
                        // calculate depth cue overlay fillstyle for texture
                        col = 255 - Ceil(col);
                        fillStyle = "rgba(0,0,0," + (1.0 - (col / 255)) + ")";
                     }
                     this.renderPolygon(ctx, obj, face, fillStyle);
                     break;
                  }
                  
                  case "lightsource":
                  {
                     // are there any lightsources defined?
                     if (lights.length === 0)
                     {
                        // calculate colour to use based on normal vector to default view-point vector
                        // use angle already calculated as they are identical
                        c = face.color;
                        r = Ceil(angle * (c[0] / PI));
                        g = Ceil(angle * (c[1] / PI));
                        b = Ceil(angle * (c[2] / PI));
                        if (face.texture === null)
                        {
                           // lit colour fill
                           fillStyle = "rgb(" + r + "," + g + "," + b + ")";
                        }
                        else
                        {
                           // calculate lit overlay fillstyle for texture
                           fillStyle = "rgba(0,0,0," + (1.0 - angle * ONEOPI) + ")";
                        }
                        this.renderPolygon(ctx, obj, face, fillStyle);
                     }
                     else
                     {
                        // perform a pass for each light - a simple linear-additive lighting model
                        r = g = b = 0;
                        for (var i=0, j=lights.length, light, lit; i<j; i++)
                        {
                           light = lights[i];
                           // TODO: investigate angle inversion
                           angle = PI - light.worldvector.thetaTo2(face.worldnormal);
                           // surface is lit by the current light - apply lighting model based on theta angle
                           // linear distance falloff - each light is additive to the total
                           lit = angle * ((1.0 / light.worldvector.distance(face.worldnormal)) * light.intensity) / PI;
                           // apply each colour component based on light colour (specified as 0.0->1.0 value)
                           r += (lit * light.color[0]);
                           g += (lit * light.color[1]);
                           b += (lit * light.color[2]);
                        }
                        
                        // clamp max lit values
                        if (r > 1.0) r = 1.0;
                        if (g > 1.0) g = 1.0;
                        if (b > 1.0) b = 1.0;
                        
                        // finally multiply into the original face colour - converting to 0-255 range
                        c = face.color;
                        var rgb = Ceil(r*c[0]) + "," + Ceil(g*c[1]) + "," + Ceil(b*c[2]);
                        if (face.texture === null)
                        {
                           // lit colour fill
                           fillStyle = "rgb(" + rgb + ")";
                        }
                        else
                        {
                           // calculate lit overlay fillstyle for texture
                           fillStyle = "rgba(" + rgb + "," + (1.0 - (r + g + b) * 0.33333) + ")";
                        }
                        this.renderPolygon(ctx, obj, face, fillStyle);
                     }
                     break;
                  }
               }
            }
         }
      },
      
      /**
       * Render a polygon faces to the given canvas context.
       * 
       * If a texture is present, it is rendered and the given fillStyle is also applied
       * as an overlay (transparency is assumed in the given fillStyle) to provide a lighting
       * effect on the texture.
       * If no texture is present, the polygon is rendered with the given fillStyle.
       * 
       * @method renderPolygon
       * @param ctx {Object} Canvas context
       * @param obj {K3D.K3DObject} The object to render
       * @param face {Object} The face object representing the polygon to render
       * @param fillStyle {string} To apply as either plain fill or texture overlay
       */
      renderPolygon: function renderPolygon(ctx, obj, face, fillStyle)
      {
         var screencoords = obj.screencoords, vertices = face.vertices;
         
         ctx.save();
         if (face.texture === null)
         {
            ctx.beginPath();
            // move to first point in the polygon
            ctx.moveTo(screencoords[vertices[0]].x, screencoords[vertices[0]].y);
            for (var i=1, j=vertices.length; i<j; i++)
            {
               // move to each additional point
               ctx.lineTo(screencoords[vertices[i]].x, screencoords[vertices[i]].y);
            }
            // no need to plot back to first point - as path closes shape automatically
            ctx.closePath();
            
            // plain colour fill - fill style generally based on rgb lighting and alpha intensity
            ctx.fillStyle = fillStyle;
            ctx.fill();
            // NOTE: can also ctx.fill() again to push fill towards edges...
            //       but stroking is more effective - if a little slow...
            // TODO: try to "inflate" i.e. expand the screencoords for the poly by 0.5 pixels?
            if (obj.fillstroke)
            {
               //ctx.strokeStyle = fillStyle;
               //ctx.lineWidth = 0.5;
               //ctx.stroke();
               ctx.fill();
            }
         }
         else
         {
            var bitmap = obj.textures[ face.texture ];
            var fRenderTriangle = function(vs, sx0, sy0, sx1, sy1, sx2, sy2)
            {
               ctx.save();
               ctx.beginPath();
               // move to first point in the triangle
               ctx.moveTo(screencoords[vs[0]].x, screencoords[vs[0]].y);
               for (var i=1, j=vs.length; i<j; i++)
               {
                  // move to each additional point
                  ctx.lineTo(screencoords[vs[i]].x, screencoords[vs[i]].y);
               }
               // no need to plot back to first point - as path closes shape automatically
               ctx.closePath();
               // textured fill - clip to the shape boundry or image will leak out
               ctx.clip();
               
               // Textured triangle transformation code originally by Thatcher Ulrich
               // TODO: figure out if drawImage goes faster if we specify the rectangle that bounds the source coords.
               // TODO: this is far from perfect - due to perspective corrected texture mapping issues see:
               //       http://tulrich.com/geekstuff/canvas/perspective.html
               var x0 = screencoords[vs[0]].x, y0 = screencoords[vs[0]].y,
                   x1 = screencoords[vs[1]].x, y1 = screencoords[vs[1]].y,
                   x2 = screencoords[vs[2]].x, y2 = screencoords[vs[2]].y;
               
               // collapse terms
               var denom = denom = 1.0 / (sx0 * (sy2 - sy1) - sx1 * sy2 + sx2 * sy1 + (sx1 - sx2) * sy0);
               // calculate context transformation matrix
               var m11 = - (sy0 * (x2 - x1) - sy1 * x2 + sy2 * x1 + (sy1 - sy2) * x0) * denom,
                   m12 = (sy1 * y2 + sy0 * (y1 - y2) - sy2 * y1 + (sy2 - sy1) * y0) * denom,
                   m21 = (sx0 * (x2 - x1) - sx1 * x2 + sx2 * x1 + (sx1 - sx2) * x0) * denom,
                   m22 = - (sx1 * y2 + sx0 * (y1 - y2) - sx2 * y1 + (sx2 - sx1) * y0) * denom,
                   dx = (sx0 * (sy2 * x1 - sy1 * x2) + sy0 * (sx1 * x2 - sx2 * x1) + (sx2 * sy1 - sx1 * sy2) * x0) * denom,
                   dy = (sx0 * (sy2 * y1 - sy1 * y2) + sy0 * (sx1 * y2 - sx2 * y1) + (sx2 * sy1 - sx1 * sy2) * y0) * denom;
               
               ctx.transform(m11, m12, m21, m22, dx, dy);
               
               // Draw the whole texture image. Transform and clip will map it onto the correct output polygon.
               ctx.drawImage(bitmap, 0, 0);
               
               // apply optionally fill style to shade and light the texture image
               if (fillStyle)
               {
                  ctx.fillStyle = fillStyle;
                  ctx.fill();
               }
               ctx.restore();
            };
            
            // we can only render triangles - a quad must be split into two triangles
            // unfortunately anything else is not dealt with currently i.e. needs a triangle subdivision algorithm
            fRenderTriangle.call(this, vertices.slice(0, 3), 0, 0, bitmap.width, 0, bitmap.width, bitmap.height);
            if (vertices.length === 4)
            {
               var v = [];
               v.push(vertices[2]);
               v.push(vertices[3]);
               v.push(vertices[0]);
               fRenderTriangle.call(this, v, bitmap.width, bitmap.height, 0, bitmap.height, 0, 0);
            }
         }
         ctx.restore();
      }
   });
})();