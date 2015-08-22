#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cmath>

using namespace std;
class Observation {
	private:
		double *dimensions;
		int length;
	public:
		Observation(int numberOfDimensions) {
			this->length = numberOfDimensions;
			this->dimensions = new double[numberOfDimensions]; 
		}

		double& operator[](const int index) {
			return dimensions[index];
		}
		
		int getNumberOfDimensions() {
			return this->length;
		}
};

class MDDTW {
	private:	
		vector<Observation> s1;
		vector<Observation> s2;
		vector<vector<double> > d;
	
		int indexOfArrayMinimum(vector<double> arr) {
			int len = arr.size();
			int ind = 0;
			for(int i = 1; i < len; i++)
				if(arr[i] < arr[ind]) {
					ind = i;
				}
			return ind;
		}
			
	public:
		MDDTW(vector<Observation> s1, vector<Observation> s2) {
			this->s1 = s1;
			this->s2 = s2;
		}
		void normalize(vector<Observation> &s) {
			int nod = s[0].getNumberOfDimensions();
			double *max = new double[nod]();
			
			for(int i = 0; i < s.size(); i++)
				for(int j = 0; j < nod; j++)
					if(s[i][j] > max[j])
						max[j] = s[i][j];
			
			for(int i = 0; i < s.size(); i++)
				for(int j = 0; j < nod; j++)
					s[i][j] /= max[j];

		}
		void normalize() {
			normalize(this->s1);
			normalize(this->s2);
		}

		void generateMatrix() {
			d.resize(s1.size());
			for(int i = 0; i < s1.size(); i++)
				d[i].resize(s2.size());

			int nod = s1[0].getNumberOfDimensions();
			for(int i = 0; i < s1.size(); i++)
				for(int j = 0; j < s2.size(); j++) {
					double sum = 0.0;
					for(int k = 0; k < nod; k++)
						if(s1[i][k] != s2[j][k])
							sum += 1.0;
					d[i][j] = sum;
				}	
		}	
		
		void printMatrix() {
			cout << "MATRIX" << endl;
			for(int i = 0; i < d.size(); i++) {
				for(int j = 0; j < d[i].size(); j++)
					cout << d[i][j] << "\t";
				cout << endl;
			}
		}
		
		void dtwMain(string img1, string img2) {
			int MM = s1.size();
			int NN = s2.size();
			double val = 0.0;

			vector<vector<double> > D;
			D.resize(MM);
			for(int i = 0; i < MM; i++)
				D[i].resize(NN);
			
			D[0][0] = d[0][0];

			for(int m = 1; m < MM; m++) {
				val = d[m][0] + D[m-1][0];
				D[m][0] = val;
			}

			for(int n = 1; n < NN; n++) {
				val = d[0][n] + D[0][n-1];
				D[0][n] = val;
			}

			for(int m = 1; m < MM; m++)
				for(int n = 1; n < NN; n++) {
					val = min(min(D[m-1][n], D[m-1][n-1]), D[m][n-1]);
					val += d[m][n];
					D[m][n] = val;
				}

			double Dist = D[MM - 1][NN - 1];
			int m = MM -1;
			int n = NN -1;
			double k = 1.0;
			int ind = 1;

			while((m + n) != 0) {
				if(m == 0)
					n = n - 1;
				else if(n == 0)
					m = m - 1;
				else {
					vector<double> arr;
					arr.push_back(D[m-1][n]);
					arr.push_back(D[m][n-1]);
					arr.push_back(D[m-1][n-1]);
					
					ind = indexOfArrayMinimum(arr); 
					if(ind == 0) m = m - 1;
					if(ind == 1) n = n - 1;
					if(ind == 2) {
						m = m - 1;
						n = n - 1;
					}
					
				}
				k += 1.0;
				//cout << "path " << n << ", " << m << endl;
			}	
			cout << Dist / max(MM, NN);	
			//cout << "insert into results values (" << img1 << ", " << img2 << ", " << Dist << " );" << endl;
		}
					
		

};


int main(int argc, char **argv) {
	vector<Observation> s1, s2;

	if(argc != 5) {
		cout << argv[0] << " <file1> <dim1> <file2> <dim2>" << endl;
		return 0;
	}
		
	ifstream file;
	string line;

	// Reading series 1
	file.open(argv[1]);
	int ctr = 0;
	while(getline(file, line)) {
		Observation o(atoi(argv[2]));
		istringstream ss(line);
		s1.push_back(o);
		for(int i = 0; i < atoi(argv[2]); i++)
			ss >> s1[ctr][i];
		ctr++;
	}
	file.close();
	
	// Reading series 2
	file.open(argv[3]);
	ctr = 0;
	while(getline(file, line)) {
		Observation o(atoi(argv[2]));
		istringstream ss(line);
		s2.push_back(o);
		for(int i = 0; i < atoi(argv[4]); i++)
			ss >> s2[ctr][i];
		ctr++;
	}
	
	MDDTW mddtw(s1, s2);
	//mddtw.normalize();
	mddtw.generateMatrix();
	mddtw.dtwMain(argv[1], argv[3]);
	return 0;
}
