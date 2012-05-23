<?php

//$cod = isset($_REQUEST['cod']) ? $_REQUEST['cod'] : null;
$PAGE->set_url('/auth/acyt/auth.php');
$PAGE->navbar->add($CASform);
$PAGE->set_title("$site->fullname: $CASform");
$PAGE->set_heading($site->fullname);
echo $OUTPUT->header();

echo "Error " . $cod_error;
echo $OUTPUT->footer();
			
		
			
?>