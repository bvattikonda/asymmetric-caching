#include <string.h>
#include <iostream>
#include <map>
#include <utility>

using namespace std;

struct mapid{
    int length;
    map<int , int> hashes;
};

typedef struct mapid mapid;
mapid node,node1;

map<int, map<int , mapid > > Employees;
int main()
{

    node1.length = 1;
    node1.hashes[0] = 1;
    // 1) Assignment using array index notation
    //  Employees[5234][0][100] = "Mike C.";
    //Employees[3374][0][356] = "Charlie M.";
    // Employees[1923][0][678] = "David D.";
    //  Employees[7582][0][777] = "John A.";
    //  Employees[5328][0][888] = "Peter Q.";
    Employees[0][0].length = 22;
    Employees[1][0].length = 55;
    Employees[2][0].length = 66;
    //cout << "Employees[3374]=" << Employees[3374][0][356] << endl << endl;

    cout << "Map size: " << Employees.size() << endl;
    cout << "size is :" << sizeof(Employees) << endl;
    Employees[1234][0] = node1;
    cout << "VAL" << Employees[1234][0].length; 
    cout << "Map size: " << Employees.size() << endl;

    for( map<int, map<int , mapid > >::iterator ii=Employees.begin(); ii!=Employees.find(2); ++ii)
    {
        for( map<int , mapid >::iterator xx=((*ii).second).begin(); xx!=((*ii).second).end(); ++xx) 
            //	for( map<int , int>::iterator yy=((*xx).second).hashes.begin(); yy!=((*xx).second).hashes.end(); ++yy)
            cout << (*ii).first << ":" << (*xx).second.length << ": " << endl;
    }
}

