/**
 * UltraLight K3D demo
 * 
 * Copyright (C) Kevin Roast 2010
 * http://www.kevs3d.co.uk/dev
 * email: kevtoast at yahoo.com
 * twitter: @kevinroast
 * 
 * I place this code in the public domain - because it's not rocket science
 * and it won't make me any money, so do whatever you want with it, go crazy.
 * I would appreciate an email or tweet if you do anything fun with it!
 * 
 * TODO:
 *  allow manipulate of x/y/z sin/cos offsets and = or +=
 *  allow user mouse control for lights
 */

var KEY = { SHIFT:16, CTRL:17, ESC:27, RIGHT:39, UP:38, LEFT:37, DOWN:40, SPACE:32 };

/**
 * Global window onload handler
 */
function onloadHandler()
{
   var canvas = document.getElementById('canvas');
   if (iPhoneOS)
   {
      canvas.width = 320;
      canvas.height = 320;
   }
   var k3dmain = new K3D.Controller(canvas, true);
   k3dmain.fps = 50;
   
   // generate test objects
   
   // A tesselated sheet
   var waveoffset = 0;
   var size = (iPhoneOS ? 180 : 325);;
   var segments = (iPhoneOS ? 8 : 16);
   var obj = tesselatedPlane(segments, segments, 0, size);
   with (obj)
   {
      drawmode = "solid";
      shademode = "lightsource";  // one of "plain", "depthcue", "lightsource"
      doublesided = true;
      recalculateNormals = true;
      aboutx = -size/2; abouty = -size/2; aboutz = 0;
   }
   k3dmain.callback = function()
   {
      obj.ophi += (targetRotationX - (obj.ophi * RAD));
      obj.otheta += (targetRotationY - (obj.otheta * RAD));
      
      // manipulate points
      var pts = obj.points,
          offsetx = offsety = waveoffset;
      for (var i=0; i<pts.length; i++)
      {
         pts[i].z = ((Math.sin(offsetx) * RAD) + (Math.cos(offsety) * RAD)) * 1024;
         pts[i].x += (Math.sin(offsetx) * RAD) * 32;
         pts[i].y += (Math.cos(offsety) * RAD) * 64;
         offsetx += 0.1;
         offsety += 0.4;
      }
      waveoffset += 0.2;
   };
   k3dmain.addK3DObject(obj);
   
   
   // add light sources
   var light = new K3D.LightSource({x:100,y:100,z:-100}, [1.0,0.0,0.0], 120.0);
   light.addgamma = 1.5;
   k3dmain.addLightSource(light);
   
   light = new K3D.LightSource({x:-100,y:-100,z:-100}, [0.0,1.0,0.0], 120.0);
   light.addgamma = 2.5;
   k3dmain.addLightSource(light);
   
   light = new K3D.LightSource({x:100,y:-100,z:-100}, [0.0,0.0,1.0], 120.0);
   light.addgamma = 2.0;
   k3dmain.addLightSource(light);
   
   // add 3D objects to represent the light sources so they are visible in the scene
   if (!iPhoneOS)
   {
      var lightObj = new K3D.K3DObject();
      with (lightObj)
      {
         color = [255,0,0];
         addgamma = 1.5;
         drawmode = "point";
         shademode = "plain";
         linescale = 24.0;
         init([{x:100,y:100,z:-100}], [], []);
      }
      k3dmain.addK3DObject(lightObj);
      
      lightObj = new K3D.K3DObject();
      with (lightObj)
      {
         color = [0,255,0];
         drawmode = "point";
         shademode = "plain";
         addgamma = 2.5;
         linescale = 24.0;
         init([{x:-100,y:-100,z:-100}], [], []);
      }
      k3dmain.addK3DObject(lightObj);
      
      lightObj = new K3D.K3DObject();
      with (lightObj)
      {
         color = [0,0,255];
         drawmode = "point";
         shademode = "plain";
         addgamma = 2.0;
         linescale = 24.0;
         init([{x:100,y:-100,z:-100}], [], []);
      }
      k3dmain.addK3DObject(lightObj);
   }
   
   // start demo loop
   k3dmain.paused = false;
   k3dmain.tick();
   
   
   // bind document keyhandler to aid debugging
   document.onkeydown = function(event)
   {
      var keyCode = (event === null ? window.event.keyCode : event.keyCode);
      
      switch (keyCode)
      {
         case KEY.SPACE:
         {
            var obj = k3dmain.objects[0];
            switch (obj.drawmode)
            {
               case "point":
                  obj.shademode = "depthcue";
                  obj.drawmode = "wireframe";
                  break;
               case "wireframe":
                  obj.shademode = "lightsource";
                  obj.drawmode = "solid";
                  break;
               case "solid":
                  obj.shademode = "depthcue";
                obj.drawmode = "point";
                  break;
            }
            break;
         }
         
         case KEY.ESC:
         {
            k3dmain.paused = !(k3dmain.paused);
            if (!k3dmain.paused) k3dmain.tick();
            break;
         }
      }
   };
}

/**
 * Generates a K3D object of a tesselated plane 0-1 in the x-y plane
 * 
 * @param vsegs   Number of vertical segments
 * @param hsegs   Number of horizontal segments
 * @param level   Subdivision level, 0-2 (quads, 2 tris, 4 tris)
 */
function tesselatedPlane(vsegs, hsegs, level, scale)
{
   var points = [], edges = [], polys = [], hinc = scale/hsegs, vinc = scale/vsegs, c = 0;
   for (var i=0, x, y = 0; i<=vsegs; i++)
   {
      x = 0;
      for (var j=0; j<=hsegs; j++)
      {
         // generate a row of points
         points.push( {x: x, y: y, z: 0} );
         
         if (i !== 0 && j !== 0)
         {
            // generate quad
            polys.push( {vertices:[c, c-1, c-hsegs-2, c-hsegs-1]} );
         }
         
         x += hinc;
         c++;
      }
      
      y += vinc;
   }
   
   var obj = new K3D.K3DObject();
   obj.init(
      points,
      edges,
      polys
   );
   
   return obj;
}


// nifty drag/touch event capture code borrowed from Mr Doob http://mrdoob.com/
var targetRotationX = 0;
var targetRotationOnMouseDownX = 0;
var mouseX = 0;
var mouseXOnMouseDown = 0;
var targetRotationY = 0;
var targetRotationOnMouseDownY = 0;
var mouseY = 0;
var mouseYOnMouseDown = 0;

var windowHalfX = window.innerWidth / 2;
var windowHalfY = window.innerHeight / 2;

document.addEventListener('mousedown', onDocumentMouseDown, false);
document.addEventListener('touchstart', onDocumentTouchStart, false);
document.addEventListener('touchmove', onDocumentTouchMove, false);

function onDocumentMouseDown( event ) {

	event.preventDefault();
	
	document.addEventListener('mousemove', onDocumentMouseMove, false);
	document.addEventListener('mouseup', onDocumentMouseUp, false);
	document.addEventListener('mouseout', onDocumentMouseOut, false);
	
	mouseXOnMouseDown = event.clientX - windowHalfX;
	targetRotationOnMouseDownX = targetRotationX;
	mouseYOnMouseDown = event.clientY - windowHalfY;
	targetRotationOnMouseDownY = targetRotationY;
}

function onDocumentMouseMove( event )
{

	mouseX = event.clientX - windowHalfX;
	targetRotationX = targetRotationOnMouseDownX + (mouseX - mouseXOnMouseDown) * 0.02;
	mouseY = event.clientY - windowHalfY;
	targetRotationY = targetRotationOnMouseDownY + (mouseY - mouseYOnMouseDown) * 0.02;
}

function onDocumentMouseUp( event )
{

	document.removeEventListener('mousemove', onDocumentMouseMove, false);
	document.removeEventListener('mouseup', onDocumentMouseUp, false);
	document.removeEventListener('mouseout', onDocumentMouseOut, false);
}

function onDocumentMouseOut( event )
{

	document.removeEventListener('mousemove', onDocumentMouseMove, false);
	document.removeEventListener('mouseup', onDocumentMouseUp, false);
	document.removeEventListener('mouseout', onDocumentMouseOut, false);
}

function onDocumentTouchStart( event )
{
	if (event.touches.length == 1)
	{
		event.preventDefault();

		mouseXOnMouseDown = event.touches[0].pageX - windowHalfX;
		targetRotationOnMouseDownX = targetRotationX;
		mouseYOnMouseDown = event.touches[0].pageY - windowHalfY;
		targetRotationOnMouseDownY = targetRotationY;
	}
}

function onDocumentTouchMove( event )
{
	if (event.touches.length == 1)
	{
		event.preventDefault();
		
		mouseX = event.touches[0].pageX - windowHalfX;
		targetRotationX = targetRotationOnMouseDownX + (mouseX - mouseXOnMouseDown) * 0.05;
		mouseY = event.touches[0].pageY - windowHalfY;
		targetRotationY = targetRotationOnMouseDownY + (mouseX - mouseYOnMouseDown) * 0.05;
	}
}