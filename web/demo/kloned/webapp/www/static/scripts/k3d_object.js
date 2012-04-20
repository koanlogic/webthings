/**
 * K3D.BaseObject class
 * 
 * Abstract base class functionality for all K3D objects.
 */
(function()
{
   /**
    * K3D.BaseObject Constructor
    */
   K3D.BaseObject = function()
   {
      // init a 3x3 multidimensonal matrix array
      this.matrix = new Array(3);
      for (var i=0; i<3; i++)
      {
         this.matrix[i] = new Array(3);
      }
      this.angles = new Array(6);
      
      return this;
   };
   
   /**
    * K3D.BaseObject prototype
    */
   K3D.BaseObject.prototype =
   {
      matrix: null,
      angles: null,
      offx: 0, offy: 0, offz: 0,
      aboutx: 0, abouty: 0, aboutz: 0,
      ogamma: 0, otheta: 0, ophi: 0,
      addgamma: 0, addtheta: 0, addphi: 0,
      velx: 0, vely: 0, velz: 0,
      bminx: 0, bminy: 0, bminz: 0, bmaxx: 0, bmaxy: 0, bmaxz: 0,
      doublesided: false,
      
      /**
       * Populate the combined XYZ rotation matrix given the current angular rotation
       * 
       * @method calcMatrix
       */
      calcMatrix: function()
      {
         var angles = this.angles, matrix = this.matrix;
         
         // using standard combined XYZ rotation matrix
         angles[0] = Sin(this.ogamma * RAD);
         angles[1] = Cos(this.ogamma * RAD);
         angles[2] = Sin(this.otheta * RAD);
         angles[3] = Cos(this.otheta * RAD);
         angles[4] = Sin(this.ophi * RAD);
         angles[5] = Cos(this.ophi * RAD);
         
         matrix[0][0] = angles[5] * angles[1];
         matrix[1][0] = -(angles[5] * angles[0]);
         matrix[2][0] = angles[4];
         matrix[0][1] = (angles[2] * angles[4] * angles[1]) + (angles[3] * angles[0]);
         matrix[1][1] = (angles[3] * angles[1]) - (angles[2] * angles[4] * angles[0]);
         matrix[2][1] = -(angles[2] * angles[5]);
         matrix[0][2] = (angles[2] * angles[0]) - (angles[3] * angles[4] * angles[1]);
         matrix[1][2] = (angles[2] * angles[1]) + (angles[3] * angles[4] * angles[0]);
         matrix[2][2] = angles[3] * angles[5];
      },
      
      /**
       * Transform object coords to world coords based on current offsets and rotation matrix.
       * 
       * @method transformToWorld
       */
      transformToWorld: function()
      {
      },
      
      /**
       * Routine to calculate and perform all transformations including sorting of object
       * ready for rendering a frame render.
       * 
       * @method executePipeline
       */
      executePipeline: function()
      {
         // inc angles
         this.ogamma += this.addgamma;
         this.otheta += this.addtheta;
         this.ophi   += this.addphi;
         
         // add velocities
         this.offx += this.velx;
         this.offy += this.vely;
         this.offz += this.velz;
         
         // check for bounce box edges, reverse velocities if needed
         if (this.offx < this.bminx || this.offx > this.bmaxx) this.velx *= -1;
         if (this.offy < this.bminy || this.offy > this.bmaxy) this.vely *= -1;
         if (this.offz < this.bminz || this.offz > this.bmaxz) this.velz *= -1;
         
         // call the transformation routines
         this.calcMatrix();
         this.transformToWorld();
      }
   };
})();


/**
 * K3D.K3DObject class
 * 
 * Common functionality for K3D renderable objects.
 */
(function()
{
   /**
    * K3D.K3DObject Constructor
    */
   K3D.K3DObject = function()
   {
      K3D.K3DObject.superclass.constructor.call(this);
      this.textures = [];
      
      return this;
   };
   
   /**
    * K3D.K3DObject prototype
    */
   extend(K3D.K3DObject, K3D.BaseObject,
   {
      controller: null,
      worldcoords: null,
      screenx: 0,
      screeny: 0,
      depthscale: 0,          // middle point for depthcue/perspective scaling
      linescale: 2.0,         // width for wireframe line rendering
      color: null,            // color - defaults to white
      drawmode: "point",      // one of "point", "wireframe", "solid"
      shademode: "depthcue",  // one of "plain", "depthcue", "lightsource"
      sortmode: "sorted",     // one of "sorted", "unsorted"
      fillstroke: true,       // true to fill and then stroke solid polygons - else just fill
      perslevel: 512,         // perspective level multiplier - powers of 2 recommended
      scale: 0,               // initial one time scaling to be applied to coordinates
      recalculateNormals: false, // set true to recalculate polygon normals vectors each frame
      points: null,
      edges: null,
      faces: null,
      screencoords: null,
      averagez: null,
      textures: null,
      depthcueColors: null,
      
      /**
       * Object initialisation. Accepts the points, edges and faces for an object.
       * All values are passed as continuous single arrays - no sub-objects.
       * Other properties for the object, such as 'scale' should be set before this
       * method is called. It should only be called once unless the object is reused.
       * 
       * @method init
       * @param points {Array}   {x,y,z} coordinate values as an continuous single array
       * @param edges {Array}    {a,b} edge index values into the coordinate array
       * @param faces {Array}    {vertices:[p1...pN],color:[r,g,b],texture:n}
       *                         vertices - array of index values into the coordinate array
       *                         color - the RGB colour triple (optional - white is default)
       *                         texture - index into the texture list for the object (optional)
       */
      init: function(points, edges, faces)
      {
         this.points = points;
         this.edges = edges;
         this.faces = faces;
         
         // init the world and screen coordinate object arrays
         // they are reused each frame - saving object creation time
         this.worldcoords = new Array(points.length + faces.length);
         for (var i=0, j=this.worldcoords.length; i<j; i++)
         {
            this.worldcoords[i] = {x:0, y:0, z:0};
         }
         this.screencoords = new Array(points.length);
         for (var i=0, j=this.screencoords.length; i<j; i++)
         {
            this.screencoords[i] = {x:0, y:0};
         }
         
         // scale the object if required
         if (this.scale !== 0)
         {
            for (var i=0, j=this.points.length; i<j; i++)
            {
               points[i].x *= this.scale;
               points[i].y *= this.scale;
               points[i].z *= this.scale;
            }
         }
         
         // set default object colour if plain rendering mode
         if (this.color === null)
         {
            this.color = [255,255,255];
         }
         
         // build depthcue colour lookup table for object
         this.depthcueColors = new Array(256);
         for (var c=0,r,g,b; c<256; c++)
         {
            r = this.color[0] * (c/255);
            g = this.color[1] * (c/255);
            b = this.color[2] * (c/255);
            this.depthcueColors[c] = "rgb(" + Ceil(r) + "," + Ceil(g) + "," + Ceil(b) + ")";
         }
         
         // calculate normal vectors for face data - and set default colour
         // value if not supplied in the data set
         for (var i=0, j=faces.length, vertices, x1, y1, z1, x2, y2, z2; i<j; i++)
         {
            // First calculate normals from 3 points on the poly:
            // Vector 1 = Vertex B - Vertex A
            // Vector 2 = Vertex C - Vertex A
            vertices = faces[i].vertices;
            x1 = points[vertices[1]].x - points[vertices[0]].x;
            y1 = points[vertices[1]].y - points[vertices[0]].y;
            z1 = points[vertices[1]].z - points[vertices[0]].z;
            x2 = points[vertices[2]].x - points[vertices[0]].x;
            y2 = points[vertices[2]].y - points[vertices[0]].y;
            z2 = points[vertices[2]].z - points[vertices[0]].z;
            // save the normal vector as part of the face data structure
            faces[i].normal = calcNormalVector(x1, y1, z1, x2, y2, z2);
            
            // Apply default face colour if none set
            if (!faces[i].color)
            {
               faces[i].color = this.color;
            }
            if (faces[i].texture === undefined)
            {
               faces[i].texture = null;
            }
         }
      },
      
      /**
       * @param controller {K3D.Controller} parent controller
       * @param screenWidth {Number} Width of the screen canvas area
       * @param screenHeight {Number} Height of the screen canvas area
       */
      setController: function(controller, screenWidth, screenHeight)
      {
         this.controller = controller;
         
         if (screenWidth)
         {
            // screen centre point
            this.screenx = screenWidth/2;
            this.screeny = screenHeight/2;
            
            // depth scaling factor - defaults to screenx
            this.depthscale = this.screenx;
            
            // init object bounding box and variables to defaults
            this.bminx = -this.screenx;
            this.bminy = -this.screeny;
            this.bminz = -this.screenx;
            this.bmaxx = this.screenx;
            this.bmaxy = this.screeny;
            this.bmaxz = this.screenx;
         }
      },
      
      /**
       * Transform object coords to world coords based on current offsets and rotation matrix.
       * 
       * @method transformToWorld
       */
      transformToWorld: function()
      {
         var x, y, z;
         var points = this.points, worldcoords = this.worldcoords,
             faces = this.faces, matrix = this.matrix;
         var ax = this.aboutx, ay = this.abouty, az = this.aboutz,
             offx = this.offx, offy = this.offy, offz = this.offz;
         
         // matrix rows
         var matrix0 = matrix[0],
             matrix1 = matrix[1],
             matrix2 = matrix[2];
         
         // transform object vertices
         for (var i=0, len=points.length; i<len; i++)
         {
            x = points[i].x + ax;                 // add origin offsets, allowing an object to
            y = points[i].y + ay;                 // move the local origin to any point in 3D space
            z = points[i].z + az;
            
            // perform matrix multiplication and add the offsets which allow an object
            // to rotate at a distance from the local origin
            
            worldcoords[i].x =
               (matrix0[0]*x) + (matrix0[1]*y) + (matrix0[2]*z) + offx;
            worldcoords[i].y =
               (matrix1[0]*x) + (matrix1[1]*y) + (matrix1[2]*z) + offy;
            worldcoords[i].z =
               (matrix2[0]*x) + (matrix2[1]*y) + (matrix2[2]*z) + offz;
         }
         
         // transform normal vectors - set as the "worldnormal" Vector3D property on the face object
         for (var i=0, len=faces.length, normal; i<len; i++)
         {
            normal = faces[i].normal;
            x = normal.x;
            y = normal.y;
            z = normal.z;
            
            faces[i].worldnormal = new Vector3D(
               (matrix0[0]*x) + (matrix0[1]*y) + (matrix0[2]*z),
               (matrix1[0]*x) + (matrix1[1]*y) + (matrix1[2]*z),
               (matrix2[0]*x) + (matrix2[1]*y) + (matrix2[2]*z));
         }
      },
      
      /**
       * Perspective calculation to transform 3D world coords to 2D screen coords.
       * 
       * @method transformToScreen
       */
      transformToScreen: function()
      {
         var x, y, z;
         var worldcoords = this.worldcoords, screencoords = this.screencoords;
         var screenx = this.screenx, screeny = this.screeny, perslevel = this.perslevel;
         
         // perform simple perspective transformation
         for (var i=0, len=this.points.length; i<len; i++)
         {
            x = worldcoords[i].x;
            y = worldcoords[i].y;
            z = worldcoords[i].z + perslevel;
            
            // stop divide by zero
            if (z === 0) z = 0.001;
            
            screencoords[i].x = ((x * perslevel) / z) + screenx;
            screencoords[i].y = screeny - ((y * perslevel) / z);
         }
      },
      
      /**
       * Routine to calculate and perform all transformations including sorting of object
       * ready for rendering a frame render.
       * 
       * @method executePipeline
       */
      executePipeline: function()
      {
         // if set, recalculate normal vectors for face data - as points have moved
         if (this.recalculateNormals)
         {
            var faces = this.faces,
                pts = this.points;
            for (var i=0, j=faces.length, vertices, x1, y1, z1, x2, y2, z2; i<j; i++)
            {
               // First calculate normals from 3 points on the poly:
               // Vector 1 = Vertex B - Vertex A
               // Vector 2 = Vertex C - Vertex A
               vertices = faces[i].vertices;
               x1 = pts[vertices[1]].x - pts[vertices[0]].x;
               y1 = pts[vertices[1]].y - pts[vertices[0]].y;
               z1 = pts[vertices[1]].z - pts[vertices[0]].z;
               x2 = pts[vertices[2]].x - pts[vertices[0]].x;
               y2 = pts[vertices[2]].y - pts[vertices[0]].y;
               z2 = pts[vertices[2]].z - pts[vertices[0]].z;
               
               // save the normal vector as part of the face data structure
               faces[i].normal = calcNormalVector(x1, y1, z1, x2, y2, z2);
            }
         }
         
         // call superclass transformation and projection routines
         K3D.K3DObject.superclass.executePipeline.call(this);
         this.transformToScreen();
         
         // sort object by distance using the appropriate renderer
         this.controller.getRenderer(this.drawmode).sortByDistance(this);
      },
      
      /**
       * Routine to execute the renderer for this object.
       * 
       * @param ctx {Object} Canvas context
       * @method executeRenderer
       */
      executeRenderer: function(ctx)
      {
         this.controller.getRenderer(this.drawmode).renderObject(this, ctx);
      },
      
      /**
       * Calculate the average Z coord for the object within the world space.
       * This value is used by the parent controller to sort the list of objects for rendering.
       * 
       * @method calculateAverageZ
       * @return {Number}
       */
      calculateAverageZ: function()
      {
         var av = 0,
             worldcoords = this.worldcoords
         
         for (var i=0, len=this.points.length; i<len; i++)
         {
            av += worldcoords[i].z;
         }
         
         this.averagez = av / this.points.length;
      }
   });
})();
