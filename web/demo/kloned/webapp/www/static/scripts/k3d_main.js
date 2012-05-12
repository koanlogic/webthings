/**
 * Canvas K3D library.
 * 
 * Software rendering of 3D objects using the 2D canvas context.
 * 
 * Copyright (C) Kevin Roast 2010
 * http://www.kevs3d.co.uk/dev
 * email: kevtoast at yahoo.com
 * twitter: @kevinroast
 * 
 * 26/11/09 First version
 * 26/05/10 Added code to maintain framerate
 * 01/06/10 Updated with additional features for UltraLight demo
 * 09/06/10 Implemented texture mapping for polygons
 * 01/03/11 Various refactoring and minor features, fixes
 * 
 * There is no documentation for this library yet, other than the code comments
 * and the various demo scripts - see k3ddemos.js, ultralight.js for examples.
 * 
 * I place this code in the public domain - because it's not rocket science
 * and it won't make me any money, so do whatever you want with it, go crazy.
 * I would appreciate an email or tweet if you do anything fun with it!
 */

var DEBUG = {};

/**
 * K3D root namespace.
 *
 * @namespace K3D
 */
if (typeof K3D == "undefined" || !K3D)
{
   var K3D = {};
}
