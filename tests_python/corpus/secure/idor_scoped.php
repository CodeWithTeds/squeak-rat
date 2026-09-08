<?php
namespace App\Http\Controllers;
use App\Models\Patient;
use Illuminate\Http\Request;
class SafePatientController {
    public function update(Request $request, Patient $patient) {
        // Secure: branch check
        if ($patient->branch_id !== branchId()) abort(403);
        // Or via query scope
        $patient = patientQuery()->findOrFail($patient->id);
        $patient->update($request->validated());
        return $patient;
    }
}
