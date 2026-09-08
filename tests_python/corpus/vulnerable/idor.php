<?php
namespace App\Http\Controllers;
use App\Models\Patient;
use Illuminate\Http\Request;
class PatientController {
    // Vulnerable IDOR: no branch_id check
    public function update(Request $request, Patient $patient) {
        $patient->update($request->all());
        return $patient;
    }
    public function show(Patient $patient) {
        return $patient;
    }
}
