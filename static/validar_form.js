
        function validateForm() {
            const fileName = document.forms["criticalFileForm"]["fileName"].value;
            const fileContent = document.forms["criticalFileForm"]["fileContent"].value;
            const encryptionAlgorithm = document.forms["criticalFileForm"]["encryptionAlgorithm"].value;
            const encryptionDate = document.forms["criticalFileForm"]["encryptionDate"].value;

            if (fileName === "" || fileContent === "" || encryptionAlgorithm === "" || encryptionDate === "") {
                alert("Todos los campos son obligatorios.");
                return false;
            }

            const datePattern = /^\d{2}\/\d{2}\/\d{4}$/;
            if (!datePattern.test(encryptionDate)) {
                alert("La fecha de encriptación debe tener el formato DD/MM/AAAA.");
                return false;
            }

            return true;
        }
