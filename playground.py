
                        fetch(`http://127.0.0.1:8000/clinic/allusers?limit=500&page=1`, {
                            method: "GET",
                            headers: {
                                "Content-Type": "application/json",
                            },
                        })
                            .then((response) => response.json())
                            .then((data) => {
                                // Handle the response from the API

                                let optionsHTML = '<option selected disabled>Select Name</option>';
                                const getRecipientOptions = document.getElementById("inputClinic");
                                for (const obj of data.Result.filter(
                                    (obj) => obj.clinic_id === selectedClinicId)) {
                                    const optionHTML = `<option value=${obj.staff_id}>${obj.first_name} ${obj.last_name}</option>`;
                                    optionsHTML += optionHTML;
                                }
                                getClinicOptions.innerHTML = optionsHTML;
