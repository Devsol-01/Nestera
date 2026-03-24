export class HospitalPatientDto {
    patientId: string;
    name: string;
    dateOfBirth: string;
    contactNumber?: string;
    email?: string;
}

export class HospitalDiagnosisDto {
    code: string;
    description: string;
    severity?: 'low' | 'medium' | 'high' | 'critical';
}

export class HospitalTreatmentDto {
    treatmentId: string;
    description: string;
    cost: number;
    date: string;
}

export class HospitalClaimDataDto {
    claimId: string;
    patient: HospitalPatientDto;
    diagnoses: HospitalDiagnosisDto[];
    treatments: HospitalTreatmentDto[];
    totalAmount: number;
    admissionDate: string;
    dischargeDate?: string;
    hospitalId: string;
    hospitalName: string;
    status: 'pending' | 'verified' | 'rejected';
}

export class HospitalVerificationDto {
    claimId: string;
    verified: boolean;
    verificationDate: string;
    verifiedBy: string;
    notes?: string;
}
