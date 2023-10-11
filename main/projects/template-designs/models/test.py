from bus import Bus
from base import BaseModel

data = [
{
"bus_id": 29565,
"sideno": 3535,
"noseats": 65
},
{
"bus_id": 29566,
"sideno": 3537,
"noseats": 65
}
]


for d in data:
    p = Bus(**d)
    p.save()
