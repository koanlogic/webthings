/**
 * K3D demos
 * 
 * Copyright (C) Kevin Roast 2010
 * http://www.kevs3d.co.uk/dev
 * email: kevtoast at yahoo.com
 * twitter: @kevinroast
 * 
 * 26/11/09 First version
 * 
 * I place this code in the public domain - because it's not rocket science
 * and it won't make me any money, so do whatever you want with it, go crazy.
 * I would appreciate an email or tweet if you do anything fun with it!
 */

var KEY = { SHIFT:16, CTRL:17, ESC:27, RIGHT:39, UP:38, LEFT:37, DOWN:40, SPACE:32,
            A:65, E:69, L:76, P:80, R:82, Z:90 };

var bitmaps = [];

/**
 * Global window onload handler
 */
function onloadHandler()
{
   // get the images loading
   bitmaps.push(new Image());
   bitmaps.push(new Image());
   var loader = new Preloader();
   loader.addImage(bitmaps[0], 'images/texture4.png');
   loader.addImage(bitmaps[1], 'images/texture5.png');
   
   // start the demos once all images have been loaded
   loader.onLoadCallback(init);
}

function init()
{
   // canvas demo areas
   var canvas1 = document.getElementById('canvas1');
   var canvas2 = document.getElementById('canvas2');
   var canvas3 = document.getElementById('canvas3');
   var canvas4 = document.getElementById('canvas4');
   var canvas5 = document.getElementById('canvas5');
   
   var k3dmain1 = new K3D.Controller(canvas1);
   var k3dmain2 = new K3D.Controller(canvas2);
   var k3dmain3 = new K3D.Controller(canvas3);
   var k3dmain4 = new K3D.Controller(canvas4);
   var k3dmain5 = new K3D.Controller(canvas5);
   
   
   // generate test objects
   
   // A snake of cubes
   for (var i=0, j=24; i<j; i++)
   {
      var obj = new K3D.K3DObject();
      obj.ophi = (360 / j) * i;
      obj.otheta = (180 / j) * i;
      with (obj)
      {
         drawmode = "wireframe";
         addgamma = 0.5; addtheta = -1.0; addphi = -0.75;
         aboutx = 100; abouty = -100; aboutz = -25;
         scale = 15;
         init(
            [{x:-1,y:1,z:-1}, {x:1,y:1,z:-1}, {x:1,y:-1,z:-1}, {x:-1,y:-1,z:-1}, {x:-1,y:1,z:1}, {x:1,y:1,z:1}, {x:1,y:-1,z:1}, {x:-1,y:-1,z:1}],
            [{a:0,b:1}, {a:1,b:2}, {a:2,b:3}, {a:3,b:0}, {a:4,b:5}, {a:5,b:6}, {a:6,b:7}, {a:7,b:4}, {a:0,b:4}, {a:1,b:5}, {a:2,b:6}, {a:3,b:7}],
            [{color:[255,0,0],vertices:[0,1,2,3]},{color:[0,255,0],vertices:[0,4,5,1]},{color:[0,0,255],vertices:[1,5,6,2]},{color:[255,255,0],vertices:[2,6,7,3]},{color:[0,255,255],vertices:[3,7,4,0]},{color:[255,0,255],vertices:[7,6,5,4]}]
         );
      }
      k3dmain1.addK3DObject(obj);
   }
   
   
   // distribute points on the surface of a sphere in a spiral
   var N = 400;
   var pts = [], edges = [];
   var s = 3.6/Math.sqrt(N);
   var len = 0;
   var dz = 2.0/N;
   var z = 1 - dz/2;
   for (var k=0; k<N; k++)
   {
      var r = Math.sqrt(1 - z*z);
      pts.push({x: Math.cos(len)*r*100, y: Math.sin(len)*r*100, z: z*100});
      if (k !== 0)
      {
         edges.push({a: k-1, b: k});
      }
      z = z - dz;
      len = len + s/r;
   }
   
   // points spiral sphere
   var obj1 = new K3D.K3DObject();
   with (obj1)
   {
      addgamma = 1.0; addtheta = 1.0; addphi = -0.5;
      linescale = 4.0;
   }
   obj1.init(pts, edges, []);
   k3dmain2.addK3DObject(obj1);
   
   // wireframe spiral sphere
   var obj2 = new K3D.K3DObject();
   with (obj2)
   {
      drawmode = "wireframe";
      addgamma = 1.0; addtheta = -0.5; addphi = 0.25;
   }
   obj2.init(pts, edges, []);
   k3dmain4.addK3DObject(obj2);
   
   
   // Icosahedron
   // Generator code from "Tessellation of sphere" http://student.ulb.ac.be/~claugero/sphere/index.html
   var obj = new K3D.K3DObject();
   var t = (1+Math.sqrt(5))/2;
   var tau = t/Math.sqrt(1+t*t);
   var one = 1/Math.sqrt(1+t*t);
   with (obj)
   {
      drawmode = "solid";
      shademode = "lightsource";
      fillstroke = false;
      aboutx = 0; abouty = 0; aboutz = 0;
      addgamma = 0.5; addtheta = -0.4; addphi = 0.6;
      scale = 100;
      linescale = 4.0;
      init(
         [{x:tau,y:one,z:0}, {x:-tau,y:one,z:0}, {x:-tau,y:-one,z:0}, {x:tau,y:-one,z:0}, {x:one,y:0,z:tau}, {x:one,y:0,z:-tau}, {x:-one,y:0,z:-tau}, {x:-one,y:0,z:tau}, {x:0,y:tau,z:one}, {x:0,y:-tau,z:one}, {x:0,y:-tau,z:-one}, {x:0,y:tau,z:-one}],
         [{a:4,b:8}, {a:8,b:7}, {a:7,b:4}, {a:7,b:9}, {a:9,b:4}, {a:5,b:6}, {a:6,b:11}, {a:11,b:5}, {a:5,b:10}, {a:10,b:6}, {a:0,b:4}, {a:4,b:3}, {a:3,b:0}, {a:3,b:5}, {a:5,b:0}, {a:2,b:7}, {a:7,b:1}, {a:1,b:2}, {a:1,b:6}, {a:6,b:2}, {a:8,b:0}, {a:0,b:11}, {a:11,b:8}, {a:11,b:1}, {a:1,b:8}, {a:9,b:10}, {a:10,b:3}, {a:3,b:9}, {a:9,b:2}, {a:2,b:10} ],
         [{color:[255,255,255],vertices:[4, 8, 7]}, {color:[255,255,0],vertices:[4, 7, 9]}, {color:[0,255,255],vertices:[5, 6, 11]}, {color:[128,0,255],vertices:[5, 10, 6]}, {color:[0,0,255],vertices:[0, 4, 3]}, {color:[255,0,0],vertices:[0, 3, 5]}, {color:[0,255,0],vertices:[2, 7, 1]}, {color:[255,0,0],vertices:[2, 1, 6]}, {color:[128,128,128],vertices:[8, 0, 11]}, {color:[255,128,0],vertices:[8, 11, 1]}, {color:[0,128,255],vertices:[9, 10, 3]}, {color:[255,0,128],vertices:[9, 2, 10]}, {color:[0,128,255],vertices:[8, 4, 0]}, {color:[128,255,0],vertices:[11, 0, 5]}, {color:[0,255,128],vertices:[4, 9, 3]}, {color:[128,255,255],vertices:[5, 3, 10]}, {color:[255,128,255],vertices:[7, 8, 1]}, {color:[128,0,255],vertices:[6, 1, 11]}, {color:[0,255,128],vertices:[7, 2, 9]}, {color:[255,0,255],vertices:[6, 10, 2]}]
      );
   }
   k3dmain3.addK3DObject(obj);
   
   
   // tesselated sphere - strips of tris have been converted to quads
   var obj = new K3D.K3DObject();
   obj.textures.push(bitmaps[0]);
   obj.textures.push(bitmaps[1]);
   with (obj)
   {
      drawmode = "solid";
      shademode = "lightsource";
      addgamma = 0.3; addtheta = 0.5; addphi = -0.4;
      ophi = 45; ogamma = 45; otheta = 45;
      scale = 100;
      linescale = 4.0;
      init(
         [{x:0.0000,y:0.0000,z:1.0000}, {x:0.0000,y:0.3827,z:0.9239}, {x:-0.1464,y:0.3536,z:0.9239},
          {x:-0.2706,y:0.2706,z:0.9239}, {x:-0.3536,y:0.1464,z:0.9239}, {x:-0.3827,y:0.0000,z:0.9239},
          {x:-0.3536,y:-0.1464,z:0.9239}, {x:-0.2706,y:-0.2706,z:0.9239}, {x:-0.1464,y:-0.3536,z:0.9239},
          {x:0.0000,y:-0.3827,z:0.9239}, {x:0.1464,y:-0.3536,z:0.9239}, {x:0.2706,y:-0.2706,z:0.9239},
          {x:0.3536,y:-0.1464,z:0.9239}, {x:0.3827,y:0.0000,z:0.9239}, {x:0.3536,y:0.1464,z:0.9239},
          {x:0.2706,y:0.2706,z:0.9239}, {x:0.1464,y:0.3536,z:0.9239}, {x:0.0000,y:0.7071,z:0.7071},
          {x:-0.2706,y:0.6533,z:0.7071}, {x:-0.5000,y:0.5000,z:0.7071}, {x:-0.6533,y:0.2706,z:0.7071},
          {x:-0.7071,y:0.0000,z:0.7071}, {x:-0.6533,y:-0.2706,z:0.7071}, {x:-0.5000,y:-0.5000,z:0.7071},
          {x:-0.2706,y:-0.6533,z:0.7071}, {x:0.0000,y:-0.7071,z:0.7071}, {x:0.2706,y:-0.6533,z:0.7071},
          {x:0.5000,y:-0.5000,z:0.7071}, {x:0.6533,y:-0.2706,z:0.7071}, {x:0.7071,y:0.0000,z:0.7071},
          {x:0.6533,y:0.2706,z:0.7071}, {x:0.5000,y:0.5000,z:0.7071}, {x:0.2706,y:0.6533,z:0.7071},
          {x:0.0000,y:0.9239,z:0.3827}, {x:-0.3536,y:0.8536,z:0.3827}, {x:-0.6533,y:0.6533,z:0.3827},
          {x:-0.8536,y:0.3536,z:0.3827}, {x:-0.9239,y:0.0000,z:0.3827}, {x:-0.8536,y:-0.3536,z:0.3827},
          {x:-0.6533,y:-0.6533,z:0.3827}, {x:-0.3536,y:-0.8536,z:0.3827}, {x:0.0000,y:-0.9239,z:0.3827},
          {x:0.3536,y:-0.8536,z:0.3827}, {x:0.6533,y:-0.6533,z:0.3827}, {x:0.8536,y:-0.3536,z:0.3827},
          {x:0.9239,y:0.0000,z:0.3827}, {x:0.8536,y:0.3536,z:0.3827}, {x:0.6533,y:0.6533,z:0.3827},
          {x:0.3536,y:0.8536,z:0.3827}, {x:0.0000,y:1.0000,z:0.0000}, {x:-0.3827,y:0.9239,z:0.0000},
          {x:-0.7071,y:0.7071,z:0.0000}, {x:-0.9239,y:0.3827,z:0.0000}, {x:-1.0000,y:0.0000,z:0.0000},
          {x:-0.9239,y:-0.3827,z:0.0000}, {x:-0.7071,y:-0.7071,z:0.0000}, {x:-0.3827,y:-0.9239,z:0.0000},
          {x:0.0000,y:-1.0000,z:0.0000}, {x:0.3827,y:-0.9239,z:0.0000}, {x:0.7071,y:-0.7071,z:0.0000},
          {x:0.9239,y:-0.3827,z:0.0000}, {x:1.0000,y:0.0000,z:0.0000}, {x:0.9239,y:0.3827,z:0.0000},
          {x:0.7071,y:0.7071,z:0.0000}, {x:0.3827,y:0.9239,z:0.0000}, {x:0.0000,y:0.9239,z:-0.3827},
          {x:-0.3536,y:0.8536,z:-0.3827}, {x:-0.6533,y:0.6533,z:-0.3827}, {x:-0.8536,y:0.3536,z:-0.3827},
          {x:-0.9239,y:0.0000,z:-0.3827}, {x:-0.8536,y:-0.3536,z:-0.3827}, {x:-0.6533,y:-0.6533,z:-0.3827},
          {x:-0.3536,y:-0.8536,z:-0.3827}, {x:0.0000,y:-0.9239,z:-0.3827}, {x:0.3536,y:-0.8536,z:-0.3827},
          {x:0.6533,y:-0.6533,z:-0.3827}, {x:0.8536,y:-0.3536,z:-0.3827}, {x:0.9239,y:0.0000,z:-0.3827},
          {x:0.8536,y:0.3536,z:-0.3827}, {x:0.6533,y:0.6533,z:-0.3827}, {x:0.3536,y:0.8536,z:-0.3827},
          {x:0.0000,y:0.7071,z:-0.7071}, {x:-0.2706,y:0.6533,z:-0.7071}, {x:-0.5000,y:0.5000,z:-0.7071},
          {x:-0.6533,y:0.2706,z:-0.7071}, {x:-0.7071,y:0.0000,z:-0.7071}, {x:-0.6533,y:-0.2706,z:-0.7071},
          {x:-0.5000,y:-0.5000,z:-0.7071}, {x:-0.2706,y:-0.6533,z:-0.7071}, {x:0.0000,y:-0.7071,z:-0.7071},
          {x:0.2706,y:-0.6533,z:-0.7071}, {x:0.5000,y:-0.5000,z:-0.7071}, {x:0.6533,y:-0.2706,z:-0.7071},
          {x:0.7071,y:0.0000,z:-0.7071}, {x:0.6533,y:0.2706,z:-0.7071}, {x:0.5000,y:0.5000,z:-0.7071},
          {x:0.2706,y:0.6533,z:-0.7071}, {x:0.0000,y:0.3827,z:-0.9239}, {x:-0.1464,y:0.3536,z:-0.9239},
          {x:-0.2706,y:0.2706,z:-0.9239}, {x:-0.3536,y:0.1464,z:-0.9239}, {x:-0.3827,y:0.0000,z:-0.9239},
          {x:-0.3536,y:-0.1464,z:-0.9239}, {x:-0.2706,y:-0.2706,z:-0.9239}, {x:-0.1464,y:-0.3536,z:-0.9239},
          {x:0.0000,y:-0.3827,z:-0.9239}, {x:0.1464,y:-0.3536,z:-0.9239}, {x:0.2706,y:-0.2706,z:-0.9239},
          {x:0.3536,y:-0.1464,z:-0.9239}, {x:0.3827,y:0.0000,z:-0.9239}, {x:0.3536,y:0.1464,z:-0.9239},
          {x:0.2706,y:0.2706,z:-0.9239}, {x:0.1464,y:0.3536,z:-0.9239}, {x:0.0000,y:0.0000,z:-1.0000} ],
         [],
         [{vertices:[0,1,2]}, {vertices:[0,2,3]}, {vertices:[0,3,4]}, {vertices:[0,4,5]}, {vertices:[0,5,6]}, {vertices:[0,6,7]}, {vertices:[0,7,8]}, {vertices:[0,8,9]}, {vertices:[0,9,10]},
          {vertices:[0,10,11]}, {vertices:[0,11,12]}, {vertices:[0,12,13]}, {vertices:[0,13,14]}, {vertices:[0,14,15]}, {vertices:[0,15,16]}, {vertices:[0,16,1]}, {vertices:[1,17,18,2]},
          {vertices:[2,18,19,3]}, {vertices:[3,19,20,4]}, {vertices:[4,20,21,5]}, {vertices:[5,21,22,6]}, {vertices:[6,22,23,7]},
          {vertices:[7,23,24,8]}, {vertices:[8,24,25,9]}, {vertices:[9,25,26,10]}, {vertices:[10,26,27,11]}, 
          {vertices:[11,27,28,12]}, {vertices:[12,28,29,13]}, {vertices:[13,29,30,14]}, {vertices:[14,30,31,15]}, {vertices:[15,31,32,16]},
          {vertices:[16,32,17,1]}, {vertices:[17,33,34,18]}, {vertices:[18,34,35,19]}, {vertices:[19,35,36,20]}, 
          {vertices:[20,36,37,21]}, {vertices:[21,37,38,22]}, {vertices:[22,38,39,23]}, {vertices:[23,39,40,24]}, {vertices:[24,40,41,25]},
          {vertices:[25,41,42,26]}, {vertices:[26,42,43,27]}, {vertices:[27,43,44,28]}, {vertices:[28,44,45,29]}, 
          {vertices:[29,45,46,30]}, {vertices:[30,46,47,31]}, {vertices:[31,47,48,32]}, {vertices:[32,48,33,17]},
          {vertices:[33,49,50,34],texture:0}, {vertices:[34,50,51,35],texture:0}, {vertices:[35,51,52,36],texture:0}, {vertices:[36,52,53,37],texture:0}, {vertices:[37,53,54,38],texture:0}, 
          {vertices:[38,54,55,39],texture:0}, {vertices:[39,55,56,40],texture:0}, {vertices:[40,56,57,41],texture:0}, {vertices:[41,57,58,42],texture:0}, {vertices:[42,58,59,43],texture:0},
          {vertices:[43,59,60,44],texture:0}, {vertices:[44,60,61,45],texture:0}, {vertices:[45,61,62,46],texture:0}, {vertices:[46,62,63,47],texture:0}, 
          {vertices:[47,63,64,48],texture:0}, {vertices:[48,64,49,33],texture:0},
          {vertices:[49,65,66,50],texture:1}, {vertices:[50,66,67,51],texture:1}, {vertices:[51,67,68,52],texture:1},
          {vertices:[52,68,69,53],texture:1}, {vertices:[53,69,70,54],texture:1}, {vertices:[54,70,71,55],texture:1}, {vertices:[55,71,72,56],texture:1}, 
          {vertices:[56,72,73,57],texture:1}, {vertices:[57,73,74,58],texture:1}, {vertices:[58,74,75,59],texture:1}, {vertices:[59,75,76,60],texture:1}, {vertices:[60,76,77,61],texture:1},
          {vertices:[61,77,78,62],texture:1}, {vertices:[62,78,79,63],texture:1}, {vertices:[63,79,80,64],texture:1}, {vertices:[64,80,65,49],texture:1}, 
          {vertices:[65,81,82,66]}, {vertices:[66,82,83,67]}, {vertices:[67,83,84,68]}, {vertices:[68,84,85,69]}, {vertices:[69,85,86,70]},
          {vertices:[70,86,87,71]}, {vertices:[71,87,88,72]}, {vertices:[72,88,89,73]}, {vertices:[73,89,90,74]}, 
          {vertices:[74,90,91,75]}, {vertices:[75,91,92,76]}, {vertices:[76,92,93,77]}, {vertices:[77,93,94,78]}, {vertices:[78,94,95,79]},
          {vertices:[79,95,96,80]}, {vertices:[80,96,81,65]}, {vertices:[81,97,98,82]}, {vertices:[82,98,99,83]}, 
          {vertices:[83,99,100,84]}, {vertices:[84,100,101,85]}, {vertices:[85,101,102,86]}, {vertices:[86,102,103,87]}, {vertices:[87,103,104,88]},
          {vertices:[88,104,105,89]}, {vertices:[89,105,106,90]}, {vertices:[90,106,107,91]}, {vertices:[91,107,108,92]}, 
          {vertices:[92,108,109,93]}, {vertices:[93,109,110,94]}, {vertices:[94,110,111,95]}, {vertices:[95,111,112,96]}, {vertices:[96,112,97,81]},
          {vertices:[113,98,97]}, {vertices:[113,99,98]}, {vertices:[113,100,99]}, {vertices:[113,101,100]}, {vertices:[113,102,101]}, {vertices:[113,103,102]}, {vertices:[113,104,103]}, {vertices:[113,105,104]},
          {vertices:[113,106,105]}, {vertices:[113,107,106]}, {vertices:[113,108,107]}, {vertices:[113,109,108]}, {vertices:[113,110,109]}, {vertices:[113,111,110]}, {vertices:[113,112,111]}, {vertices:[113,97,112]} ]
         );
   }
   k3dmain5.addK3DObject(obj);
   
   
   // add lightsource for solid object demo
   var light = new K3D.LightSource({x:70,y:70,z:-70}, [0.0,0.75,1.0], 70.0);
   light.addgamma = 2.5;
   k3dmain5.addLightSource(light);
   light = new K3D.LightSource({x:-50,y:-50,z:-70}, [1.0,1.0,0.0], 70.0);
   light.addgamma = 1.5;
   k3dmain5.addLightSource(light);
   // add an object to represent the lightsource so it is visible in the scene
   var lightObj = new K3D.K3DObject();
   with (lightObj)
   {
      color = [0,192,255];
      drawmode = "point";
      shademode = "plain";
      addgamma = 2.5;
      linescale = 16.0;
      init([{x:70,y:70,z:-70}], [], []);
   }
   k3dmain5.addK3DObject(lightObj);
   lightObj = new K3D.K3DObject();
   with (lightObj)
   {
      color = [255,255,0];
      drawmode = "point";
      shademode = "plain";
      addgamma = 1.5;
      linescale = 16.0;
      init([{x:-50,y:-50,z:-70}], [], []);
   }
   k3dmain5.addK3DObject(lightObj);
   
   // render first frames
   k3dmain1.frame();
   // use motion blur background fill
   k3dmain2.fillStyle = "rgba(0,0,0, 0.50)";
   k3dmain2.frame();
   k3dmain3.frame();
   k3dmain4.fillStyle = "rgba(0,0,0, 0.50)";
   k3dmain4.frame();
   k3dmain5.frame();
   
   // start main demo
   k3dmain1.paused = false;
   k3dmain1.frame();
   
   
   // bind document keyhandler to aid debugging
   document.onkeydown = function(event)
   {
      var keyCode = (event === null ? window.event.keyCode : event.keyCode);
      
      switch (keyCode)
      {
         case KEY.SPACE:
         {
            var obj = k3dmain3.objects[0];
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
      }
   };
}
