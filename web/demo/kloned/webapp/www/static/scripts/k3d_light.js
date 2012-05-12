/**
 * K3D.LightSource class
 * 
 * A simple linear lighting model lightsource for solid object rendering.
 */
(function()
{
   /**
    * K3D.LightSource Constructor
    * 
    * @param location {Object} Location of the light {x,y,z}
    * @param color {Array} Colour of the light - each component specified from 0.0->1.0 in an array [r,g,b]
    * @param intensity {Number} Light itensity - float value generally 0.0->100.0
    */
   K3D.LightSource = function(location, color, intensity)
   {
      K3D.LightSource.superclass.constructor.call(this);
      
      this.location = location;
      this.color = color;
      this.intensity = intensity;
      
      return this;
   };
   
   /**
    * K3D.LightSource prototype
    */
   extend(K3D.LightSource, K3D.BaseObject,
   {
      /* light colour [r,g,b] */
      color: null,
      
      /* light intensity 0.0-1.0 */
      intensity: null,
      
      /** location coordinate {x, y, z} */
      location: null,
      
      /** transformed location to world coordinates as a Vector3D */
      worldvector: null,
      
      /**
       * Transform object coords to world coords based on current offsets and rotation matrix.
       * 
       * @method transformToWorld
       */
      transformToWorld: function()
      {
         var matrix = this.matrix;
         
         // transform light location
         var x = this.location.x + this.aboutx;
         var y = this.location.y + this.abouty;
         var z = this.location.z + this.aboutz;
         
         // perform matrix multiplication and add the offsets which allow an object
         // to rotate at a distance from the local origin
         this.worldvector = new Vector3D(
            (matrix[0][0]*x) + (matrix[0][1]*y) + (matrix[0][2]*z) + this.offx,
            (matrix[1][0]*x) + (matrix[1][1]*y) + (matrix[1][2]*z) + this.offy,
            (matrix[2][0]*x) + (matrix[2][1]*y) + (matrix[2][2]*z) + this.offz);
      }
   });
})();
