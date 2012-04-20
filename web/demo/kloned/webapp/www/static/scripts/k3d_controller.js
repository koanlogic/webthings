/**
 * K3D.BaseController class.
 * 
 * Controller for a number of K3D objects. Maintains and sorts the object list. Provides
 * a function to processes each object during the render loop.
 */
(function()
{
   /**
    * K3D.BaseController constructor
    */
   K3D.BaseController = function()
   {
      this.objects = [];
      this.lights = [];
      this.renderers = [];
      this.renderers["point"] = new K3D.PointRenderer();
      this.renderers["wireframe"] = new K3D.WireframeRenderer();
      this.renderers["solid"] = new K3D.SolidRenderer();
   };
   
   K3D.BaseController.prototype =
   {
      renderers: null,
      objects: null,
      lights: null,
      sort: true,
      
      /**
       * Add a K3D object to the list of objects for rendering
       */
      addK3DObject: function(obj)
      {
         obj.setController(this);
         this.objects.push(obj);
      },
      
      /**
       * Add a light source to the list of available lights
       */
      addLightSource: function(light)
      {
         this.lights.push(light);
      },
      
      /**
       * @param drawmode {string} drawing mode constant
       * @return the renderer for the given drawing mode
       */
      getRenderer: function(drawmode)
      {
         return this.renderers[drawmode];
      },
      
      /**
       * Render processing frame - should be called via a setInterval() function or similar
       * 
       * @param ctx {object} Canvas context
       */
      processFrame: function(ctx)
      {
         // execute transformation pipeline for each object and light
         var objects = this.objects;
         for (var i = 0, len = objects.length; i < len; i++)
         {
            objects[i].executePipeline();
         }
         var lights = this.lights;
         for (var i = 0, len = lights.length; i < len; i++)
         {
            lights[i].executePipeline();
         }
         
         // sort objects in average Z order
         if (this.sort)
         {
            objects.forEach(function clearAverageZ(el, i, a)
            {
               el.averagez = null;
            });
            objects.sort(function sortObjects(a, b)
            {
               // ensure we have an average z coord for the objects to test
               if (a.averagez === null)
               {
                  a.calculateAverageZ();
               }
               if (b.averagez === null)
               {
                  b.calculateAverageZ();
               }
               return (a.averagez < b.averagez ? 1 : -1);
            });
         }
         
         // render objects to the canvas context
         for (var i = 0, len = objects.length; i < len; i++)
         {
            ctx.save();
            objects[i].executeRenderer(ctx);
            ctx.restore();
         }
      }
   };
})();


/**
 * K3D.Controller class.
 * 
 * Default canvas based controller, manages the canvas render context.
 * Provides the default frame() function for the render loop.
 */
(function()
{
   /**
    * K3D.Controller constructor
    * 
    * @param canvas {Object}  The canvas to render the object list into.
    */
   K3D.Controller = function(canvas, nopause)
   {
      K3D.Controller.superclass.constructor.call(this);
      
      this.canvas = canvas;
      
      // bind click event to toggle rendering loop on/off
      var me = this;
      if (!nopause)
      {
         canvas.onclick = function(event)
         {
            me.paused = !me.paused;
            if (!me.paused)
            {
               me.frame();
            }
         };
      }
   };
   
   extend(K3D.Controller, K3D.BaseController,
   {
      canvas: null,
      clearBackground: true,     // true if the Controller is responsible for clearing the canvas
      fillStyle: null,
      paused: true,
      callback: null,
      fps: 40,
      lastFrameStart: 0,
      
      /**
       * Add a K3D object to the list of objects for rendering
       */
      addK3DObject: function(obj)
      {
         obj.setController(this, this.canvas.width, this.canvas.height);
         this.objects.push(obj);
      },
      
      /**
       * Leave this method for backward compatability
       */
      tick: function()
      {
         this.frame();
      },
      
      /**
       * Render frame - should be called via a setInterval() function
       */
      frame: function()
      {
         var frameStart = new Date().getTime();
         
         if (this.callback)
         {
            this.callback.call(this);
         }
         
         var ctx = this.canvas.getContext('2d');
         
         // TODO: store screencoord render boundries - implement rectangle culled clearing between frames?
         if (this.clearBackground)
         {
            if (this.fillStyle !== null)
            {
               ctx.fillStyle = this.fillStyle;
               ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
            }
            else
            {
               ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            }
         }
         
         // execute super class method to process render pipelines
         this.processFrame(ctx);
         
         // calculate interval required for smooth animation
         var delay = 1000/this.fps;
         var frameTime = (new Date().getTime() - frameStart);
         if (!this.paused)
         {
            var me = this;
            setTimeout(function(){me.frame()}, delay - frameTime <= 0 ? 1 : delay - frameTime);
         }
         if (DEBUG && DEBUG.FPS)
         {
            ctx.fillStyle = "grey";
            ctx.fillText("TPF: " + frameTime, 4, 48);
            var frameFPS = Math.round(1000 / (frameStart - this.lastFrameStart));
            ctx.fillText("FPS: " + frameFPS, 4, 64);
         }
         this.lastFrameStart = frameStart;
      }
   });
})();
