<?php

/** 
* proxy.php
*
* Performs a cross-domain HTTP request to KINK
* (not possible via AJAX).
**/

$daurl = 'http://localhost:5683/acc';
$handle = fopen($daurl, "r");
if ($handle) {
    while (!feof($handle)) {
        $buffer = fgets($handle, 4096);
        echo $buffer;
    }
    fclose($handle);
}

?>
