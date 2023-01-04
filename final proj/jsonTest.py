import json
import os

jsonStr =  '{ "data" : {"name" : "Filipe", "points": 3 }, "signature" : "signatureeee", "certificate" : "certtttt" }'
             
jsonFile = json.loads(jsonStr)

# If File Exists
if os.path.exists('pointsTest.json'):
    # Read Data from JSON
    with open('pointsTest.json', 'r') as f:
        data = json.load(f)
        # Score Exists = False
        exists = False
        
        for score in data['scores']: 
            # If Score Exists 
            if score["data"]["name"] == jsonFile["data"]["name"]:
                data["scores"][data['scores'].index(score)]["data"]["points"] = score["data"]["points"] +jsonFile["data"]["points"]
                print("Score Updated!")
                exists = True
                break
            
        # If Score does not Exists 
        if not exists:   
            data["scores"].append(jsonFile)
            print("Score Added!")
        f.close()
        
    # Write to JSON  
    with open('pointsTest.json', 'w') as f:
        json.dump(data, f)
        f.close()
        
    print("Json Updated!")
        
# If File does not Exists 
else:
    with open('pointsTest.json', 'w') as f:
        # Create first Score
        data = {"scores" : [jsonFile]}
        json.dump(data, f)
        f.close()
    print("Json Created!")