<?php

/** 
* accel_values.php
*
* Placeholder resource, responding to and ajax call
* with a randomly picked accelerometer value
*
**/

$i = rand ( 0 , 5 );
$l = array("0, 0, 250", // starting position
"0, 0, -250", // upside down
"250,0,0", // Facing the camera
"125, 0, 125", //  angled towards the camera
"-125, 0, 125", // angled towards the front
"-125, -125, 125"); // angled towards the front/left  
echo $l[$i];

?>