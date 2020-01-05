#include <stdio.h>
#include <math.h>

/******************************************************************************
 * This program takes an initial estimate of m and c and finds the associated 
 * rms error. It is then as a base to generate and evaluate 8 new estimates, 
 * which are steps in different directions in m-c space. The best estimate is 
 * then used as the base for another iteration of "generate and evaluate". This 
 * continues until none of the new estimates are better than the base. This is
 * a gradient search for a minimum in mc-space.
 * 
 * To compile:
 *   cc -o lr_courseworka_115 lr_courseworka_115.c -lm
 * 
 * To run:
 *   ./lr_courseworka_115
 * 
 * Dr Kevan Buckley, University of Wolverhampton, 2018
 *****************************************************************************/


typedef struct point_t {
  double b;
  double s;
} point_t;

int n_data = 1000;

point_t data[];

void print_data() {
  int i;
  printf("b,s\n");
  for(i=0; i<n_data; i++) {
    printf("%0.2lf,%0.2lf\n", data[i].b, data[i].s);
  }
}

int main() {
  print_data();
  return 0;
}


point_t data[] = {
  {76.80,141.84},{73.91,133.16},{65.59,135.84},{77.08,144.27},
  {83.32,166.24},{72.64,139.99},{69.42,137.04},{82.61,146.08},
  {73.55,125.13},{68.93,133.75},{65.26,120.97},{78.19,141.47},
  { 1.86,40.06},{69.95,122.74},{ 2.32,35.00},{53.17,120.38},
  {29.55,74.36},{73.51,119.81},{73.29,129.87},{99.93,182.89},
  {28.58,80.09},{98.15,165.02},{87.87,154.79},{52.68,90.48},
  {95.88,175.41},{85.56,155.25},{70.52,118.85},{ 2.72,20.43},
  {58.10,100.25},{62.74,118.35},{18.29,50.38},{15.05,60.11},
  {22.10,47.04},{25.33,65.98},{65.87,128.00},{51.66,127.14},
  {79.95,133.20},{38.12,88.95},{98.50,159.87},{21.00,52.36},
  {43.80,91.36},{85.22,138.76},{39.41,89.16},{15.74,26.40},
  {67.15,108.89},{37.24,88.37},{35.35,67.93},{91.42,158.11},
  {46.60,82.54},{37.68,85.78},{55.62,113.91},{ 2.02,21.36},
  {84.91,166.55},{ 8.85,35.27},{ 6.00,35.70},{98.54,172.74},
  {33.24,67.28},{15.37,54.73},{81.85,138.13},{13.21,35.51},
  {18.19,39.85},{74.19,133.01},{84.49,162.54},{90.24,167.41},
  {61.38,121.57},{20.98,61.98},{29.03,76.72},{53.11,110.71},
  {38.99,82.43},{59.75,101.30},{25.68,53.90},{34.02,67.91},
  {84.81,131.19},{77.47,145.16},{58.10,92.30},{56.57,94.05},
  {74.41,158.89},{53.02,107.64},{23.68,77.01},{48.88,102.20},
  {83.06,143.91},{15.93,61.90},{27.01,59.22},{78.96,134.04},
  {75.43,127.47},{94.50,158.75},{40.92,78.41},{91.71,151.42},
  { 1.97,41.60},{11.47,45.38},{54.42,114.94},{80.83,150.03},
  {30.04,64.02},{44.17,94.37},{10.27,43.22},{88.84,139.06},
  {33.72,89.85},{97.14,172.86},{75.24,136.22},{58.14,130.17},
  {71.66,146.04},{39.01,85.49},{12.53,74.58},{19.86,59.84},
  {90.36,162.15},{42.05,85.60},{11.34,46.50},{38.25,82.33},
  {56.03,102.81},{79.53,152.62},{45.92,73.14},{73.10,120.38},
  {38.44,69.17},{ 3.18,46.09},{89.02,151.21},{79.64,140.20},
  {59.32,115.04},{ 4.82,28.94},{22.23,90.79},{78.46,119.28},
  {94.31,160.98},{76.89,141.23},{ 5.95,29.48},{67.27,133.32},
  {44.10,89.40},{69.11,137.57},{79.19,151.24},{30.05,67.92},
  {52.81,128.68},{65.71,116.48},{79.58,134.68},{56.10,103.72},
  {25.96,87.41},{99.04,171.89},{55.01,100.03},{52.79,107.16},
  {79.91,144.45},{32.81,65.02},{73.50,118.30},{64.85,123.67},
  {67.87,114.03},{37.47,82.32},{13.30,56.88},{26.45,57.69},
  {83.68,125.67},{ 2.12,39.21},{ 6.53,35.89},{76.61,118.93},
  {11.18,29.40},{33.59,70.34},{49.78,110.01},{ 4.33,36.51},
  {62.64,126.51},{17.96,64.00},{36.71,66.56},{88.59,159.96},
  {95.07,175.93},{74.10,142.50},{74.76,135.49},{10.21,48.66},
  {25.75,85.88},{50.01,94.95},{39.80,93.54},{14.44,62.55},
  {79.73,147.16},{29.17,65.58},{18.52,52.66},{54.73,100.30},
  {56.56,89.64},{87.15,137.47},{37.12,74.12},{62.75,120.94},
  {60.14,110.71},{95.94,170.44},{66.99,137.00},{31.35,85.48},
  {79.39,130.65},{40.20,91.54},{68.85,136.78},{16.09,58.59},
  {39.57,77.44},{88.74,164.96},{51.84,74.76},{14.10,52.03},
  {66.02,117.94},{ 8.71,49.97},{87.28,144.57},{34.63,63.25},
  {80.07,154.95},{67.92,127.80},{ 1.57,38.91},{12.79,50.94},
  {19.52,53.00},{68.04,127.41},{20.66,60.34},{48.99,117.19},
  {20.29,60.77},{64.41,123.36},{52.94,101.32},{29.32,63.73},
  {86.66,154.85},{73.95,127.20},{88.87,152.73},{80.97,146.15},
  {53.59,100.46},{92.23,150.49},{61.22,120.55},{46.66,107.47},
  {70.35,133.38},{77.13,146.97},{15.05,47.88},{15.43,63.59},
  {60.54,131.30},{45.81,87.73},{76.11,144.77},{39.78,84.86},
  {18.05,38.73},{96.55,179.51},{13.75,56.30},{71.24,133.26},
  { 6.04,48.27},{21.18,46.80},{53.76,123.66},{82.45,125.86},
  {18.49,53.38},{10.93,58.21},{79.28,134.70},{90.84,163.49},
  {88.23,157.72},{10.24,37.48},{ 4.06,34.97},{52.32,110.39},
  {30.49,63.88},{32.90,77.32},{80.03,135.88},{ 7.99,39.79},
  {46.58,75.04},{68.28,118.04},{36.46,79.32},{57.91,100.57},
  {42.31,97.60},{73.06,135.84},{26.16,74.49},{58.33,122.36},
  {21.83,59.63},{90.91,167.94},{67.31,103.49},{83.28,151.87},
  {18.74,52.50},{25.28,87.07},{ 0.04,48.99},{15.70,57.91},
  {69.08,122.75},{61.44,130.76},{99.28,170.25},{ 4.70,44.28},
  {21.01,51.11},{83.12,148.84},{94.96,171.58},{52.57,102.65},
  {73.17,141.20},{52.02,108.60},{89.72,160.15},{18.17,55.31},
  {37.16,79.58},{85.51,165.97},{13.61,62.15},{50.21,115.56},
  {37.08,71.23},{61.61,114.52},{50.45,91.25},{62.31,107.83},
  {89.71,143.58},{24.52,50.59},{68.68,131.27},{64.42,129.75},
  {15.32,50.66},{31.93,68.03},{73.46,139.28},{ 3.37,27.10},
  {49.84,109.19},{15.24,52.48},{63.01,128.75},{87.87,163.91},
  {72.28,129.27},{55.87,113.20},{50.08,98.45},{88.77,156.30},
  {40.90,90.24},{52.45,121.75},{34.18,75.42},{ 2.08,41.22},
  {97.76,164.01},{49.10,97.53},{ 5.78,58.18},{50.77,92.78},
  {29.77,74.05},{57.32,95.04},{62.64,127.56},{58.64,115.55},
  {39.39,109.48},{ 4.66,47.66},{16.72,56.61},{92.34,145.17},
  {42.98,105.02},{85.37,144.96},{81.34,150.80},{69.35,113.25},
  {13.61,55.21},{64.56,129.05},{99.87,174.79},{91.63,164.57},
  {23.05,91.57},{ 5.46,43.28},{27.43,84.68},{52.33,90.64},
  {20.48,69.31},{78.49,157.01},{99.77,179.69},{62.42,123.76},
  {58.35,118.29},{14.99,70.97},{62.30,121.40},{22.72,60.52},
  {99.76,161.94},{38.45,70.05},{97.83,166.09},{57.61,134.00},
  {36.54,80.11},{88.36,165.33},{29.18,83.77},{57.23,108.37},
  {72.49,135.62},{ 3.47,38.93},{65.63,129.64},{90.85,167.02},
  {87.52,172.65},{ 4.62,37.46},{18.33,43.25},{75.19,153.75},
  {45.61,100.25},{85.86,163.44},{55.67,111.10},{25.74,79.05},
  {68.37,123.11},{28.28,69.28},{38.78,98.75},{41.30,74.09},
  { 8.75,51.61},{77.69,125.88},{32.13,65.51},{58.65,108.48},
  {89.71,150.18},{47.96,93.88},{51.00,80.92},{46.89,103.89},
  {46.26,96.89},{13.87,35.50},{49.68,82.47},{84.04,140.36},
  {37.19,76.46},{ 5.07,56.07},{86.56,149.09},{92.96,159.47},
  {40.03,82.41},{ 2.90,13.57},{49.34,98.62},{ 3.27,32.40},
  {11.55,37.57},{97.95,159.99},{57.72,108.86},{57.86,110.39},
  {98.70,169.60},{88.71,148.15},{19.49,65.21},{54.49,101.01},
  {19.52,58.02},{46.56,79.03},{31.47,63.96},{61.20,128.64},
  {40.12,94.46},{46.43,96.10},{95.94,161.45},{ 6.65,38.08},
  { 0.43,36.11},{20.73,67.54},{38.92,99.40},{86.38,161.23},
  {66.40,123.71},{93.10,158.11},{99.87,171.41},{52.58,94.12},
  {98.77,172.28},{96.98,177.97},{38.77,71.09},{81.98,138.21},
  {95.55,158.03},{94.06,159.42},{73.09,136.27},{90.48,180.71},
  {48.31,90.76},{19.54,72.85},{92.72,164.87},{13.27,36.49},
  { 6.85,33.02},{15.48,57.51},{ 1.16,13.57},{88.43,161.05},
  {86.72,151.66},{63.94,112.18},{ 1.25,24.67},{74.26,138.29},
  { 1.10,29.32},{91.18,142.29},{38.38,92.64},{26.63,67.12},
  {72.40,139.89},{ 8.29,31.60},{ 0.02,39.77},{91.48,151.26},
  {42.17,86.16},{26.42,43.92},{40.27,91.64},{10.38,51.42},
  {20.00,54.18},{78.75,145.54},{12.44,47.88},{95.58,176.01},
  {27.10,66.61},{20.58,71.93},{97.79,156.01},{11.65,64.15},
  {59.69,122.96},{35.39,81.41},{22.81,50.30},{16.16,46.29},
  {84.75,142.39},{46.08,74.86},{25.67,52.99},{97.77,155.99},
  {87.77,160.64},{33.83,67.16},{37.26,85.91},{74.81,128.92},
  {68.78,132.78},{ 3.84,35.74},{21.67,53.12},{89.23,163.96},
  {80.66,156.05},{ 2.80,31.53},{33.31,45.40},{41.13,87.83},
  {23.59,74.18},{24.78,61.40},{78.06,125.39},{23.63,67.79},
  {97.24,163.05},{57.61,92.44},{99.91,182.09},{81.92,142.72},
  { 3.80,39.87},{22.59,62.84},{40.81,89.25},{54.14,103.07},
  {75.21,113.13},{49.96,95.61},{67.06,129.33},{55.40,87.85},
  {31.59,75.65},{48.21,96.10},{41.34,99.65},{56.25,106.02},
  { 9.52,53.66},{70.69,131.01},{47.96,107.16},{18.06,52.70},
  {20.40,43.03},{79.46,158.10},{22.82,68.78},{84.27,158.87},
  { 7.56,48.96},{21.12,68.79},{39.89,84.94},{86.02,147.43},
  {14.47,64.44},{90.07,154.50},{63.38,133.42},{37.80,76.64},
  {68.66,130.16},{62.35,131.18},{14.86,43.80},{ 6.96,17.52},
  {16.70,50.42},{ 9.81,27.11},{12.19,36.12},{44.33,78.86},
  {31.61,82.77},{97.48,168.20},{10.81,27.75},{13.75,56.21},
  {34.29,80.84},{43.69,105.87},{54.68,108.96},{79.73,147.53},
  {61.62,128.04},{73.20,127.82},{36.97,87.76},{12.32,58.22},
  {34.46,100.48},{22.89,59.72},{84.91,151.54},{43.43,96.84},
  {51.08,113.87},{92.00,143.99},{76.91,123.46},{45.28,88.12},
  {27.89,79.00},{ 4.47,55.66},{25.29,66.38},{88.23,154.76},
  {48.29,97.80},{73.62,116.98},{79.61,137.75},{86.57,154.09},
  {67.17,129.19},{25.80,70.83},{87.25,161.52},{64.78,127.78},
  {67.09,130.55},{85.80,135.92},{46.81,87.55},{71.45,149.02},
  {75.36,137.01},{30.13,73.87},{ 7.97,45.84},{66.93,135.67},
  { 6.84,52.61},{63.42,119.19},{33.74,78.18},{ 6.98,39.25},
  {98.47,171.90},{28.73,66.90},{94.63,157.45},{95.85,170.74},
  {31.42,77.86},{10.33,43.96},{ 7.50,28.74},{85.43,160.97},
  {72.92,120.06},{70.63,141.20},{89.19,154.32},{ 1.28,49.29},
  {13.59,46.03},{61.11,125.53},{ 5.27,64.32},{19.77,44.45},
  {95.49,158.30},{10.00,39.59},{97.35,181.66},{96.40,159.11},
  {25.14,69.61},{89.18,141.99},{90.52,154.82},{69.02,143.17},
  {72.48,135.19},{87.45,149.80},{97.18,163.59},{30.97,68.55},
  {20.60,72.67},{47.12,94.02},{51.85,96.36},{23.80,78.13},
  {87.26,150.01},{14.46,59.40},{99.77,144.05},{46.96,88.39},
  {58.25,109.93},{85.37,147.30},{23.46,90.32},{98.69,171.96},
  {16.95,46.18},{42.41,101.69},{10.42,59.19},{75.26,126.84},
  {30.39,81.77},{37.02,93.26},{58.49,110.09},{89.10,162.93},
  {68.61,132.29},{76.17,144.98},{45.37,91.14},{39.45,89.34},
  {63.16,129.10},{19.58,53.00},{23.00,64.87},{88.56,157.52},
  {80.32,141.54},{55.62,115.72},{49.44,109.66},{98.69,175.29},
  {88.65,166.47},{59.01,127.46},{34.62,73.17},{41.17,99.55},
  {87.75,147.26},{94.03,156.18},{55.08,108.49},{98.89,173.47},
  {49.82,90.69},{87.73,160.65},{16.47,46.46},{41.34,79.62},
  {83.15,166.44},{14.92,57.61},{21.80,67.82},{37.69,69.32},
  {49.33,86.80},{90.91,147.04},{93.07,149.61},{25.44,59.18},
  {17.22,49.18},{28.17,72.65},{ 0.77,38.97},{90.87,163.43},
  {74.63,137.34},{16.55,49.30},{ 1.12,35.94},{91.42,163.41},
  { 7.28,48.60},{43.66,104.54},{ 2.20,40.26},{63.34,124.06},
  {14.44,41.91},{21.21,88.98},{13.05,38.15},{90.07,165.55},
  {14.23,59.03},{97.65,177.44},{52.59,89.72},{79.61,144.27},
  {30.57,63.58},{99.86,169.58},{14.72,51.55},{31.54,70.10},
  {59.28,109.68},{99.01,155.79},{ 4.13,26.79},{74.04,116.03},
  {70.44,139.98},{64.71,123.78},{ 5.33,42.21},{71.19,126.62},
  {50.18,98.86},{ 2.53,39.51},{23.81,77.92},{40.89,81.47},
  {98.40,187.24},{39.88,73.90},{39.42,76.83},{30.46,75.54},
  {59.20,109.15},{89.00,145.34},{46.42,88.82},{32.54,72.77},
  { 4.00,45.27},{ 4.85,30.22},{81.77,135.31},{ 0.16,30.49},
  {67.78,133.13},{ 0.90,25.09},{58.59,118.38},{15.94,58.65},
  {14.91,46.73},{43.82,89.21},{16.87,46.15},{43.14,96.83},
  { 6.28,27.61},{47.25,99.92},{ 4.17,57.60},{90.64,166.35},
  {91.91,170.54},{ 8.13,34.07},{76.90,154.01},{12.52,41.40},
  {95.64,176.97},{95.90,168.69},{88.69,167.66},{48.93,105.62},
  {79.17,139.57},{67.41,107.70},{61.38,117.56},{89.48,166.48},
  {19.16,57.11},{66.62,133.08},{44.79,102.21},{16.93,63.03},
  { 8.98,39.98},{66.95,123.43},{53.25,116.97},{93.25,163.17},
  { 1.37,32.85},{ 2.97,34.85},{80.87,150.60},{ 0.78,41.96},
  {72.69,143.99},{26.02,85.06},{75.36,139.16},{85.18,162.42},
  {36.34,73.88},{ 8.84,34.15},{84.81,148.96},{78.96,137.06},
  {92.35,178.55},{54.26,127.97},{78.63,131.07},{59.43,105.79},
  {52.22,96.59},{26.93,59.49},{50.87,91.55},{45.79,94.03},
  { 6.65,28.84},{56.94,103.37},{81.17,150.08},{35.22,80.75},
  {25.29,67.81},{45.85,94.53},{88.97,170.12},{83.69,126.64},
  {87.32,142.75},{95.98,184.02},{91.57,173.77},{31.69,64.55},
  { 3.54,23.12},{50.07,94.48},{18.35,47.95},{30.13,68.41},
  {68.27,105.85},{93.84,164.65},{59.83,123.21},{11.37,48.82},
  {16.11,42.53},{43.48,97.29},{46.11,93.28},{15.92,54.20},
  {47.99,82.39},{52.76,92.39},{54.61,98.69},{26.05,62.64},
  { 2.70,27.78},{45.88,101.97},{69.70,133.74},{93.08,148.81},
  {94.21,145.15},{26.78,87.99},{39.36,75.81},{62.67,103.44},
  {60.39,105.91},{31.61,91.69},{46.66,102.22},{40.21,71.78},
  {17.32,59.38},{89.24,159.24},{ 8.69,37.85},{41.27,94.31},
  {92.40,160.41},{13.84,42.44},{90.70,156.55},{ 0.42,24.58},
  {16.73,57.77},{98.89,164.23},{50.47,87.52},{61.55,99.37},
  {66.83,139.43},{97.54,179.55},{78.85,130.58},{50.54,91.24},
  {29.76,72.61},{76.44,150.84},{17.98,50.71},{60.01,128.80},
  {86.74,135.73},{23.03,79.65},{90.98,148.41},{32.64,66.55},
  {88.30,137.91},{72.69,131.75},{78.37,138.56},{ 3.06,46.75},
  {47.35,94.38},{86.94,155.23},{56.80,110.40},{27.56,54.63},
  {17.18,65.78},{88.88,160.44},{94.22,139.98},{38.53,89.02},
  {65.36,112.75},{80.71,133.50},{15.96,42.45},{48.83,95.69},
  {73.66,129.33},{45.90,98.06},{ 6.36,41.17},{ 7.74,32.66},
  { 9.30,42.57},{90.82,137.41},{19.67,52.81},{22.39,51.17},
  {42.95,93.53},{65.18,116.03},{41.10,71.11},{ 8.09,29.31},
  {84.62,146.49},{29.68,80.89},{50.05,97.61},{81.14,135.28},
  {15.61,47.81},{98.10,186.60},{39.06,87.72},{80.94,131.21},
  {15.49,33.59},{36.01,82.96},{20.29,78.53},{64.39,98.31},
  {70.45,114.03},{50.06,104.96},{97.71,173.93},{67.51,126.77},
  {27.84,68.02},{68.61,115.91},{94.33,163.94},{81.11,153.84},
  {78.52,153.73},{51.69,126.17},{19.24,50.87},{27.23,75.02},
  {17.33,62.66},{59.72,139.84},{36.70,80.89},{47.17,89.34},
  { 9.61,45.28},{45.38,84.42},{70.09,125.18},{27.52,78.87},
  {12.20,36.42},{89.21,147.16},{44.13,91.63},{99.17,166.39},
  {94.87,160.37},{24.21,75.30},{23.41,49.17},{62.28,109.53},
  {13.91,49.57},{25.50,66.32},{63.04,121.17},{38.17,74.32},
  {28.15,79.85},{77.84,157.44},{50.06,117.94},{88.97,164.45},
  {58.29,121.06},{30.98,76.85},{54.15,108.46},{46.74,115.39},
  {28.18,70.58},{98.37,157.20},{82.66,133.94},{34.16,79.28},
  {71.70,139.93},{ 9.66,38.94},{20.02,70.45},{83.99,164.25},
  {57.41,91.87},{93.45,161.27},{15.09,52.25},{46.67,104.19},
  {15.83,48.09},{56.40,115.31},{75.99,129.90},{71.95,137.67},
  {62.19,125.27},{64.79,128.82},{40.04,71.35},{37.52,78.35},
  {57.41,110.12},{59.51,113.76},{82.35,155.78},{68.11,115.06},
  {63.82,135.64},{79.09,132.29},{31.90,68.73},{86.51,140.48},
  {94.15,165.22},{25.25,68.16},{85.44,148.52},{42.71,76.69},
  {35.97,61.23},{64.06,114.99},{63.34,123.75},{45.82,103.23},
  {45.00,91.90},{ 5.05,31.45},{79.00,131.76},{37.62,72.79},
  {54.83,98.22},{ 2.45,42.63},{87.14,144.97},{16.61,58.22},
  {25.40,67.97},{52.02,109.33},{94.70,165.30},{24.56,69.39},
  {26.65,95.29},{20.21,74.69},{32.51,93.53},{77.67,150.18},
  { 7.97,53.99},{17.95,45.32},{14.08,44.40},{97.68,172.42},
  {81.04,157.46},{67.94,124.06},{15.28,61.69},{65.24,111.24},
  { 9.81,47.35},{53.35,105.71},{51.27,116.77},{92.44,176.67},
  {92.75,157.71},{96.63,170.59},{50.96,102.10},{12.59,56.64},
  {87.99,154.97},{53.27,104.83},{89.34,156.25},{89.43,144.96},
  { 4.31,29.94},{38.53,76.07},{71.29,126.18},{48.55,98.93},
  {75.68,134.51},{43.97,100.37},{49.42,94.90},{ 3.19,46.01},
  {45.93,84.87},{55.20,99.30},{52.74,104.53},{65.60,126.25},
  { 1.83,30.62},{78.75,147.10},{44.84,90.34},{94.01,165.47},
  {12.81,46.00},{ 3.20,46.31},{92.04,165.41},{24.39,70.09},
  {76.21,145.59},{42.07,99.74},{ 7.83,32.08},{98.32,168.32},
  {59.36,126.16},{63.97,128.90},{46.78,97.92},{ 6.73,29.83},
  {19.71,40.05},{33.58,73.65},{95.76,177.24},{15.76,35.10},
  { 5.13,57.23},{80.36,145.85},{81.75,164.69},{ 1.42,38.61},
  {49.30,97.65},{13.35,36.82},{27.95,63.49},{92.39,172.97},
  {69.59,122.40},{79.07,153.47},{83.63,162.86},{37.18,88.83},
  {69.71,134.76},{57.08,95.74},{88.42,154.68},{79.00,152.84},
  {85.75,142.50},{57.33,108.36},{44.82,93.00},{56.97,102.79},
  {36.56,73.41},{66.46,112.74},{ 4.01,59.76},{75.72,144.06},
  {89.60,175.98},{90.10,153.07},{16.49,51.91},{87.96,128.17},
  {31.01,67.42},{ 5.77,45.91},{ 2.92,34.29},{68.82,132.71}
};
